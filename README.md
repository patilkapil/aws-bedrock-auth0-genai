# Reference Architecture: AWS BedRock + Auth0 for GenAI



This project demonstrates a reference architecture for integrating AWS Bedrock with Auth0 to enable secure, authenticated, and authorized access to GenAI (Generative AI) applications and external data sources.

## Architecture Overview
![image (10)](https://github.com/user-attachments/assets/8036bd3e-8d6b-4b1a-a7ae-cd5053679535)

The architecture consists of the following key components:

- **User Authentication**: Users authenticate via a login experience, typically managed by Auth0, to access the GenAI application.
- **GenAI App**: The main application interface that interacts with users and manages their sessions.
- **Token Vault**: Securely stores and retrieves user tokens for downstream authorization.
- **Amazon Bedrock**: Provides foundational AI services, including Bedrock Agents and Large Language Models (LLMs).
- **Bedrock Agent**: Acts as an orchestrator, handling user requests, invoking LLMs, and coordinating with action groups for specific tasks.
- **Agent Task Function**: Executes fine-grained permission checks and async authorization logic, ensuring that only authorized actions are performed on behalf of the user.
- **External Data Sources**: Includes AWS resources, SaaS providers (e.g., Gmail, Salesforce, Atlassian, Okta), MCP servers, and APIs.

## Key Flows

1. **User Login**: Users authenticate and obtain tokens, which are securely stored in the Token Vault.
2. **Token Management**: The GenAI app retrieves and manages user tokens for secure access.
3. **Fine Grained Authorization**: The Bedrock Agent coordinates with Lambda functions to perform fine-grained and asynchronous authorization, ensuring data privacy and compliance.
4. **Data Access**: Upon successful authorization, the system accesses external data sources as permitted.

## What Does the AWS Bedrock Agent Do?

At a high level, the AWS Bedrock Agent:
- Orchestrates user requests and interactions with large language models (LLMs).
- Integrates with action groups to perform specific tasks or workflows.
- Ensures secure and authorized access to external data sources by coordinating with authorization functions.
- Acts as a bridge between the GenAI application and AWS Bedrock's AI capabilities, enabling intelligent, context-aware responses and actions.

---

This architecture ensures that AI-powered applications can securely interact with sensitive data and external services, leveraging the strengths of AWS Bedrock and Auth0 for robust authentication and authorization. 
