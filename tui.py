import seclib
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer, Input, Static
from rich.text import Text

from masker import Masker
from llm_client import call_llm


class SecureLLM(App):
    CSS = """
    Screen { background: #0b1020; }
    #panels { height: 1fr; }
    .panel { border: round #3b82f6; padding: 1 2; width: 1fr; height: 100%; }
    #p_real { border: round #ef4444; }
    #p_masked { border: round #f59e0b; }
    #p_final { border: round #22c55e; }
    #status { height: 3; border: round #6366f1; padding: 0 2; content-align: left middle; }
    Input { margin: 1 0; }
    """
    TITLE = "Secure LLM Pipeline"
    BINDINGS = [("ctrl+q", "quit", "Iesire")]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Input(placeholder="Scrie un mesaj cu date personale si apasa Enter...")
        with Horizontal(id="panels"):
            yield Static("", id="p_real", classes="panel")
            yield Static("", id="p_masked", classes="panel")
            yield Static("", id="p_final", classes="panel")
        yield Static("", id="status")
        yield Footer()

    def on_mount(self) -> None:
        master = seclib.generate_key()
        self.shares = seclib.split_secret(master, 3, 5)
        del master
        self.query_one("#p_real").border_title = "TU (date reale)"
        self.query_one("#p_masked").border_title = "PROVIDER (ce vede LLM-ul)"
        self.query_one("#p_final").border_title = "RASPUNS (demascat local)"
        self.set_status("Master key impartita 3-din-5. Cheia intreaga NU este stocata.")

    def set_status(self, msg: str) -> None:
        self.query_one("#status", Static).update(msg)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text:
            return
        event.input.value = ""
        self.query_one("#p_real", Static).update(Text(text))

        key = bytearray(seclib.combine_shares(self.shares[:3]))
        self.set_status("Cheie reconstruita in memorie (3 share-uri)...")
        try:
            m = Masker()
            masked = m.mask(text)
            self.query_one("#p_masked", Static).update(Text(masked))
            answer = call_llm(masked)
            final = m.unmask(answer)
            self.query_one("#p_final", Static).update(Text(final))
            blob = m.export_encrypted(bytes(key))
            self.set_status(
                f"Mapping criptat AES-256-GCM ({len(blob)} bytes). Cheia a fost stearsa din memorie."
            )
        finally:
            for i in range(len(key)):
                key[i] = 0


if __name__ == "__main__":
    SecureLLM().run()
