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
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

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
  _user.get("/status", (req, res) => { res.send("live"); });

  // Message retrieval routes
  _user.get("/getLastReceivedMessage", (req, res) => { 
    res.json({ result: globalThis.userStateStore[userId].lastReceivedMsg }); 
  });

  _user.get("/getLastSentMessage", (req, res) => { 
    res.json({ result: globalThis.userStateStore[userId].lastSentMsg }); 
  });

  _user.get("/getLastCircuit", (req, res) => { 
    res.json({ result: globalThis.userStateStore[userId].lastUsedCircuit }); 
  });

  // Route to receive a message
  _user.post("/message", (req, res) => {
    const { message } = req.body;
    if (message === undefined || message === null) { 
      return res.status(400).json({ error: "Message not detected" }); 
    }

    globalThis.userStateStore[userId].lastReceivedMsg = message;
    return res.send("success");
  });

  // Route to send a message
  _user.post("/sendMessage", async (req, res) => {
    try {
      const msgPayload: SendMessageBody = req.body;
  
      if (!msgPayload.message || msgPayload.destinationUserId === undefined) {
        console.log("[ERROR] Message content and recipient ID are required");
        return res.status(400).json({ error: "Message content and recipient ID are required" });
      }
  
      console.log(`[INFO] Preparing message for User ${msgPayload.destinationUserId}...`);
  
      // Fetch available nodes from the registry
      const registryResponse = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
      if (!registryResponse.ok) throw new Error("Failed to fetch node registry");
  
      const registryData = (await registryResponse.json()) as { nodes: Node[] };
      const nodeList = registryData.nodes;
  
      if (nodeList.length < 3) {
        throw new Error("Insufficient nodes available for routing.");
      }
  
      // Select 3 random nodes for routing
      const circuitNodes = [...nodeList].sort(() => 0.5 - Math.random()).slice(0, 3);
      const circuitPath = circuitNodes.map(node => node.nodeId);
      console.log(`[INFO] Circuit Path: ${circuitPath.join(" -> ")}`);
  
      // Generate symmetric keys for each hop
      const encryptionKeys = await Promise.all(circuitPath.map(() => createRandomSymmetricKey()));
  
      // Multi-layer encryption
      let encryptedMsg = msgPayload.message;
      for (let i = 2; i >= 0; i--) {
        const nextNodeId =
          i === 2
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
  
      console.log(`[INFO] Sending encrypted message to first node at ${firstNodeUrl}`);
  
      const messageResponse = await fetch(firstNodeUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: encryptedMsg }),
      });
  
      if (!messageResponse.ok) {
        throw new Error(`Failed to send message to first node (Status: ${messageResponse.status})`);
      }
  
      // Update user state after successful transmission
      
      globalThis.userStateStore[userId].lastSentMsg = msgPayload.message;
      globalThis.userStateStore[userId].lastUsedCircuit = circuitPath;
  
      console.log(`[SUCCESS] Message successfully transmitted to User ${msgPayload.destinationUserId}`);
  
      return res.json({ status: "Message successfully transmitted" });
  
    } catch (error) {
      
      return res.status(500).json({ error: "Internal error occurred during message transmission." });
    }
  });
  

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(`User ${userId} is listening on port ${BASE_USER_PORT + userId}`);
  });

  return server;
}