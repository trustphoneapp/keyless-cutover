import { createAgentInvoker } from "./invoke.mjs";
import { createKeylessAgentServer } from "./server.mjs";
import { evidenceAgent, recoveryAgent } from "./taskmaster.mjs";

const server = createKeylessAgentServer({
  evidenceInvoker: createAgentInvoker({ agent: evidenceAgent, lane: "evidence" }),
  recoveryInvoker: createAgentInvoker({ agent: recoveryAgent, lane: "recovery" }),
  apiToken: process.env.KEYLESS_API_TOKEN,
});
const port = Number(process.env.PORT ?? 8080);
server.listen(port, "0.0.0.0", () => process.stdout.write(`keyless-agent listening on ${port}\n`));
