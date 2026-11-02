"""Customer-support agents (OpenAI Agents SDK)."""

from agents import Agent, WebSearchTool, function_tool, handoff

from .billing import billing_agent

TRIAGE_PROMPT = """You are the first point of contact.
Route refund requests to Refunds and invoices to Billing."""


@function_tool(needs_approval=True)
def issue_refund(order_id: str, amount: float) -> str:
    """Refund an order."""
    return f"refunded {order_id}"


@function_tool
def lookup_order(order_id: str) -> str:
    """Look up an order."""
    return order_id


refunds_agent = Agent(
    name="Refunds",
    instructions="Handle refunds. Always confirm the amount.",
    model="gpt-4o-mini",
    tools=[issue_refund, lookup_order],
)

triage_agent = Agent(
    name="Triage",
    instructions=TRIAGE_PROMPT,
    model="gpt-4o",
    tools=[lookup_order, WebSearchTool()],
    handoffs=[refunds_agent, handoff(billing_agent)],
)
