from openai import OpenAI

client = OpenAI()

def generate(user_input):
    return client.chat.completions.create(
        model="example-model",
        messages=[{"role": "user", "content": user_input}],
    )
