def safe_prompt(user_input):
    system_prompt = "system: answer using the approved policy"
    return client.responses.create(input=system_prompt)
