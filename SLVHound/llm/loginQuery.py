from openai import OpenAI
import os

os.environ["OPENAI_API_KEY"] = ""
os.environ["OPENAI_BASE_URL"] = ""

client = OpenAI(
    api_key=os.environ.get("OPENAI_API_KEY"),
    base_url=os.environ.get("OPENAI_BASE_URL"),
)

method_code = ""

completion = client.chat.completions.create(
  model="gpt-4o",
    messages=[
        {"role": "system", "content": "You are an experienced and professional Java programmer developer. You have extensive experience in web project development."},
        {"role": "user", "content": "Determine whether the given method is a method for user login in a Java web project based on the following Java code snippet, answer with yes or no." + method_code},
    ]
)

print(completion)  
print(completion.choices[0].message)  


