"""Billing agent (OpenAI Agents SDK)."""

from agents import Agent

billing_agent = Agent(
    name="Billing",
    handoff_description="Answers invoice questions",
    instructions="Answer invoice questions only.",
    model="o3-mini",
)
