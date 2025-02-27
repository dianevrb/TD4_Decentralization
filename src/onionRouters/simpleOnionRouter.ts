import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, BASE_USER_PORT, REGISTRY_PORT } from "../config";
import { generateRsaKeyPair, exportPubKey, exportPrvKey, rsaDecrypt, symDecrypt } from "../crypto";
import { webcrypto } from "crypto";

declare global {
  var nodeKeys: Record<number, { publicKey: webcrypto.CryptoKey; privateKey: webcrypto.CryptoKey }>;
  var nodeStates: Record<number, { 
    lastEncryptedMsg: string | null;
    lastDecryptedMsg: string | null;
    lastMsgDestination: number | null;
  }>;
}

export async function simpleOnionRouter(nodeId: number) {
  if (!globalThis.nodeKeys) {
    globalThis.nodeKeys = {};
  }
  if (!globalThis.nodeKeys[nodeId]) {
    globalThis.nodeKeys[nodeId] = await generateRsaKeyPair();
  }

  if (!globalThis.nodeStates) {
    globalThis.nodeStates = {};
  }
  if (!globalThis.nodeStates[nodeId]) {
    globalThis.nodeStates[nodeId] = {
      lastEncryptedMsg: null,
      lastDecryptedMsg: null,
      lastMsgDestination: null,
    };
  }

  const { publicKey, privateKey } = globalThis.nodeKeys[nodeId];
  const publicKeyBase64 = await exportPubKey(publicKey);
  const privateKeyBase64 = await exportPrvKey(privateKey);
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  // Route de statut
  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  // Routes d'accès aux messages
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: globalThis.nodeStates[nodeId].lastEncryptedMsg });
  });

  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: globalThis.nodeStates[nodeId].lastDecryptedMsg });
  });

  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: globalThis.nodeStates[nodeId].lastMsgDestination });
  });

  // Récupération de la clé privée
  onionRouter.get("/getPrivateKey", (req, res) => {
    res.json({ result: privateKeyBase64 });
  });

  // Enregistrement automatique du nœud auprès du registre
  const registerNode = async () => {
    try {
      const response = await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          nodeId,
          pubKey: publicKeyBase64,
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error: ${response.status}`);
      }

      const data = await response.json();
      console.log("Server response:", data);
    } catch (error) {
      console.error("Error during node registration:", error);
    }
  };
  registerNode();

  // Route pour traiter les messages entrants
  onionRouter.post("/message", async (req, res) => {
    try {
      const { message }: { message: string } = req.body;

      if (message === undefined) {
        return res.status(400).json({ error: "Missing message" });
      }

      console.log(`Node ${nodeId}: Message received, decrypting...`);

      // Extraction de la clé symétrique et du message chiffré
      const encryptedSymKey = message.slice(0, 344);
      const encryptedPayload = message.slice(344);

      // Déchiffrement de la clé symétrique avec la clé privée du nœud
      const symKey = await rsaDecrypt(encryptedSymKey, privateKey);

      // Si le message est vide, on est au dernier nœud
      let decryptedPayload = encryptedPayload.length > 0 ? await symDecrypt(symKey, encryptedPayload) : "";

      // Extraction de la prochaine destination et du message
      const nextDestination = decryptedPayload.length >= 10
        ? parseInt(decryptedPayload.slice(0, 10), 10)
        : null;

      const nextMessage = decryptedPayload.length > 10 ? decryptedPayload.slice(10) : "";

      console.log(`Node ${nodeId}: ➜ Next destination: ${nextDestination ?? "Final Destination"}`);
      console.log(`Node ${nodeId}:Decrypted message: ${nextMessage.length ? nextMessage : "<EMPTY MESSAGE>"}`);
      
      
      

      // Mise à jour de l'état du nœud
      globalThis.nodeStates[nodeId].lastEncryptedMsg = message;
      globalThis.nodeStates[nodeId].lastDecryptedMsg = nextMessage;
      globalThis.nodeStates[nodeId].lastMsgDestination = nextDestination;

      // Si c'est le dernier nœud, on arrête ici
      if (nextDestination === null) {
        return res.json({ status: "Final message reached the last node", message: nextMessage });
      }

      // Déterminer si la prochaine destination est un utilisateur ou un autre nœud
      const isUser = nextDestination >= BASE_USER_PORT;
      const nextUrl = `http://localhost:${nextDestination}/message`;

      console.log(`Node ${nodeId}:Forwarding message to ${isUser ? "User" : "Node"} at ${nextUrl}`);

      // Transmettre le message au prochain destinataire
      const response = await fetch(nextUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: nextMessage }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error: ${response.status}`);
      }

      return res.json({ status: "Message decrypted and forwarded successfully" });

    } catch (error) {
      console.error(`[Node ${nodeId}] Error while decrypting the message:`, error);
      return res.status(500).json({ error: "Internal error while processing the message" });
    }
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(`Onion router ${nodeId} is listening on port ${BASE_ONION_ROUTER_PORT + nodeId}`);
  });

  return server;
}
