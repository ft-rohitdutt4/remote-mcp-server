# Expense Tracker MCP Server

A **remote MCP (Model Context Protocol) server** for tracking personal expenses, designed to be deployed on **FastMCP Cloud** and used seamlessly with **Claude Desktop**.

This server supports:
- Self-service user registration
- API-key authentication
- Per-user data isolation
- Expense CRUD operations
- Category summaries
- Cloud-friendly storage model

---

##  Features

-  **Secure Authentication**
  - User registration with email + password
  - PBKDF2-SHA256 password hashing
  - Per-user API keys
  - API key regeneration

-  **Expense Management**
  - Add expenses
  - List expenses by date range
  - Summarize expenses by category
  - Delete expenses
  - Full per-user data isolation

-  **Cloud Ready**
  - Designed for FastMCP Cloud
  - Uses ephemeral filesystem (`tempdir`)
  - Single SQLite database (easy to swap for Postgres later)

-  **Claude Compatible**
  - Works as a remote MCP server
  - Callable directly from Claude Desktop
  - Clean tool descriptions for natural language use

---