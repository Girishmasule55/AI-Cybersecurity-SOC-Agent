from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph
from typing_extensions import TypedDict

from app.core.config import get_settings
from app.schemas.soc import SecurityEventRead
from app.services.rag import PlaybookRAG


class AgentState(TypedDict):
    event: SecurityEventRead
    context: list[str]
    analysis: str
    actions: str


def _fallback_analysis(event: SecurityEventRead, context: list[str]) -> tuple[str, str]:
    summary = (
        f"{event.event_type} on {event.host} from {event.src_ip or 'unknown source'} "
        f"scored {event.risk_score:.0f}/100. Message: {event.message}"
    )
    actions = "\n".join(context) if context else "Review the event, preserve logs, and contain affected assets."
    return summary, actions


class SocAgent:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.rag = PlaybookRAG()
        self.llm = None
        if self.settings.openai_api_key:
            self.llm = ChatOpenAI(
                model=self.settings.openai_model,
                api_key=self.settings.openai_api_key,
                temperature=0,
            )
        self.graph = self._build_graph()

    def _build_graph(self):
        graph = StateGraph(AgentState)

        def retrieve(state: AgentState) -> AgentState:
            event = state["event"]
            query = f"{event.event_type} {event.severity} {event.message}"
            state["context"] = self.rag.retrieve(query)
            return state

        def reason(state: AgentState) -> AgentState:
            event = state["event"]
            if not self.llm:
                analysis, actions = _fallback_analysis(event, state["context"])
                state["analysis"] = analysis
                state["actions"] = actions
                return state

            messages = [
                SystemMessage(
                    content=(
                        "You are an AI SOC analyst. Think in ReAct style internally: "
                        "observe the event, reason about likely attack path, then answer "
                        "with a concise summary and concrete mitigation actions."
                    )
                ),
                HumanMessage(
                    content=(
                        f"Event: {event.model_dump()}\n"
                        f"Playbook context: {state['context']}\n"
                        "Return two sections: Summary and Recommended actions."
                    )
                ),
            ]
            response = self.llm.invoke(messages).content
            parts = str(response).split("Recommended actions", 1)
            state["analysis"] = parts[0].replace("Summary:", "").strip()
            state["actions"] = parts[1].strip(" :\n") if len(parts) > 1 else str(response)
            return state

        graph.add_node("retrieve", retrieve)
        graph.add_node("reason", reason)
        graph.add_edge(START, "retrieve")
        graph.add_edge("retrieve", "reason")
        graph.add_edge("reason", END)
        return graph.compile()

    def analyze(self, event: SecurityEventRead) -> tuple[str, str]:
        state = self.graph.invoke({"event": event, "context": [], "analysis": "", "actions": ""})
        return state["analysis"], state["actions"]
