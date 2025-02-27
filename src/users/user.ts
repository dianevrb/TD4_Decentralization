import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT, BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { createRandomSymmetricKey, exportSymKey, rsaEncrypt, symEncrypt } from "../crypto";
import { Node } from "../registry/registry";

declare global {
  var userStateStore: Record<number, { 
    lastReceivedMsg: string | null;
    lastSentMsg: string | null;
    lastUsedCircuit: number[] | null;
  }>;
}

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  const app = express();
  app.use(express.json());
  app.use(bodyParser.json());

  if (!globalThis.userStateStore) {
    globalThis.userStateStore = {};
  }

  if (!globalThis.userStateStore[userId]) {
    globalThis.userStateStore[userId] = {
      lastReceivedMsg: null,
      lastSentMsg: null,
      lastUsedCircuit: null
    };
  }

  // Status route
  app.get("/status", (req, res) => { res.send("live"); });

  // Message retrieval routes
  app.get("/getLastReceivedMessage", (req, res) => { 
    res.json({ result: globalThis.userStateStore[userId].lastReceivedMsg }); 
  });

  app.get("/getLastSentMessage", (req, res) => { 
    res.json({ result: globalThis.userStateStore[userId].lastSentMsg }); 
  });

  app.get("/getLastCircuit", (req, res) => { 
    res.json({ result: globalThis.userStateStore[userId].lastUsedCircuit }); 
  });

  // Route to receive a message
  app.post("/message", (req, res) => {
    const { message } = req.body;
    if (message === undefined || message === null) { 
      return res.status(400).json({ error: "Message not detected" }); 
    }

    globalThis.userStateStore[userId].lastReceivedMsg = message;
    return res.send("success");
  });

  // Route to send a message
  app.post("/sendMessage", async (req, res) => {
    try {
      const msgPayload: SendMessageBody = req.body;

      if (msgPayload.message === undefined || msgPayload.destinationUserId === undefined) {
        console.log("Message content and recipient ID are required");
        return res.status(400).json({ error: "Message content and recipient ID are required" });
      }

      // Fetch available nodes from the registry
      const registryResponse = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
      const registryData = await registryResponse.json() as { nodes: Node[] };
      const nodeList = registryData.nodes;

      // Select 3 random nodes for routing
      const circuitNodes = [...nodeList].sort(() => 0.5 - Math.random()).slice(0, 3);
      const circuitPath = circuitNodes.map(node => node.nodeId);

      // Generate symmetric keys for each hop
      const encryptionKeys = await Promise.all(circuitPath.map(() => createRandomSymmetricKey()));

      // Multi-layer encryption
      let encryptedMsg = msgPayload.message;
      for (let i = 2; i >= 0; i--) {
        const nextNodeId = i === 2 
          ? (BASE_USER_PORT + msgPayload.destinationUserId).toString() 
          : (BASE_ONION_ROUTER_PORT + circuitPath[i + 1]).toString();
        const formattedNodeId = nextNodeId.padStart(10, "0");

        encryptedMsg = await symEncrypt(encryptionKeys[i], formattedNodeId + encryptedMsg);
        const encryptedKeyBase64 = await exportSymKey(encryptionKeys[i]);
        const encryptedKey = await rsaEncrypt(encryptedKeyBase64, circuitNodes[i].pubKey);
        encryptedMsg = encryptedKey + encryptedMsg;
      }

      // Send the encrypted message to the first node
      const firstNode = circuitPath[0];
      const firstNodeUrl = `http://localhost:${BASE_ONION_ROUTER_PORT + firstNode}/message`;

      const messageResponse = await fetch(firstNodeUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: encryptedMsg }),
      });

      if (!messageResponse.ok) {
        throw new Error(`Failed to send message to first node: ${messageResponse.status}`);
      }

      // Update user state after successful transmission
      globalThis.userStateStore[userId].lastSentMsg = msgPayload.message;
      globalThis.userStateStore[userId].lastUsedCircuit = circuitPath;

      return res.json({ status: "Message successfully transmitted" });

    } catch (error) {
      console.error(`User ${userId}: Error during message transmission: ${error}` );
      return res.status(500).json({ error: "Internal error occurred during message transmission" });
    }
  });

  const server = app.listen(BASE_USER_PORT + userId, () => {
    console.log(`User ${userId} is listening on port ${BASE_USER_PORT + userId}`);
  });

  return server;
}
