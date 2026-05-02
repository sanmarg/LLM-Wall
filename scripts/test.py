import openai

client = openai.OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="not-needed",
    default_headers={"X-LLM-Provider": "ollama"},
)

print("🤖 DevOps Q&A Bot (stateless) (type 'exit' to quit)\n")

while True:
    user_input = input("You: ")

    if user_input.lower() in ["exit", "quit"]:
        print("Bot: Goodbye 👋")
        break

    response = client.chat.completions.create(
        model="llama3.2:3b",
        messages=[
            {"role": "system", "content": "You are a helpful DevOps expert assistant."},
            {"role": "user", "content": user_input}
        ],
    )

    bot_reply = response.choices[0].message.content

    print(f"Bot: {bot_reply}\n")