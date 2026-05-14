const chatContainer = document.getElementById("chat-container");
const form = document.getElementById("chat-form");
const input = document.getElementById("message-input");
const sendButton = document.getElementById("send-button");
const statusEl = document.getElementById("status");

function appendMessage({ role, content, isTyping = false }) {
  const row = document.createElement("div");
  row.className = `message-row ${role}`;

  const avatar = document.createElement("div");
  avatar.className = `avatar ${role}`;
  avatar.textContent = role === "user" ? "You" : "AI";

  const bubble = document.createElement("div");
  bubble.className = "bubble";

  if (isTyping) {
    const indicator = document.createElement("div");
    indicator.className = "typing-indicator";
    indicator.innerHTML = `
      <span class="typing-dot"></span>
      <span class="typing-dot"></span>
      <span class="typing-dot"></span>
    `;
    bubble.appendChild(indicator);
  } else {
    bubble.textContent = content;
  }

  row.appendChild(avatar);
  row.appendChild(bubble);
  chatContainer.appendChild(row);
  chatContainer.scrollTop = chatContainer.scrollHeight;

  return { row, bubble };
}

function setStatus(message, isError = false) {
  statusEl.textContent = message || "";
  statusEl.classList.toggle("error", Boolean(isError));
}

async function sendMessage(message) {
  setStatus("");

  appendMessage({ role: "user", content: message });
  const typing = appendMessage({ role: "assistant", content: "", isTyping: true });

  sendButton.disabled = true;
  input.disabled = true;

  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
    });

    typing.row.remove();

    if (!res.ok) {
      const errorBody = await res.json().catch(() => ({}));
      const detail =
        errorBody?.detail ||
        `Request failed with status ${res.status} ${res.statusText}`;
      setStatus(detail, true);
      appendMessage({
        role: "assistant",
        content: "Sorry, something went wrong talking to the model.",
      });
      return;
    }

    const data = await res.json();
    appendMessage({ role: "assistant", content: data.reply || "(no response)" });
  } catch (err) {
    typing.row.remove();
    console.error(err);
    setStatus("Network error while contacting the API.", true);
    appendMessage({
      role: "assistant",
      content: "I couldn't reach the backend. Please check the server.",
    });
  } finally {
    sendButton.disabled = false;
    input.disabled = false;
    input.focus();
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  const message = input.value.trim();
  if (!message) return;
  input.value = "";
  sendMessage(message);
});

input.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    form.dispatchEvent(new Event("submit"));
  }
});

// Initial system message
const systemRow = document.createElement("div");
systemRow.className = "message-row";
const systemBubble = document.createElement("div");
systemBubble.className = "bubble system";
systemBubble.textContent =
  "This is a local LLM chat UI. Start by asking a question. Make sure the backend is running and Ollama is installed/running with a model pulled (e.g. 'ollama pull llama3.2').";
systemRow.appendChild(systemBubble);
chatContainer.appendChild(systemRow);
chatContainer.scrollTop = chatContainer.scrollHeight;

