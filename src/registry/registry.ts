import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";
import { request } from "http";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

const registeredNodes: Node[] = [];

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  // TODO implement the status route
  _registry.get("/status", (req, res) => {res.send("live");});
  _registry.get("/users", (req: Request, res: Response): void => {res.json({ users: [] }); });
  _registry.get("/getNodeRegistry", (req: Request, res: Response): void => { res.json({ nodes: registeredNodes });});
  _registry.post("/registerNode", (req: Request, res: Response): void => {
    const node_info: RegisterNodeBody= req.body;
    if (node_info.nodeId === undefined || typeof node_info.nodeId !== "number" || !node_info.pubKey) {
      res.status(400).json({ error: "Missing nodeId or public key" });
      return;
    }
    if (registeredNodes.some(node => node.nodeId === node_info.nodeId)) {
      res.status(400).json({ error: "Node is already registered" });
      return;
    }
    registeredNodes.push({ nodeId: node_info.nodeId, pubKey: node_info.pubKey });
    res.json({ message: "Node registered successfully" });

  });
  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`Registry is listening on port ${REGISTRY_PORT}`);
  });
  return server;
}
