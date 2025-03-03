#!/usr/local/bin/python3
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from langchain.prompts import PromptTemplate,ChatPromptTemplate
from langchain.chains import LLMChain, SimpleSequentialChain

from langchain.prompts import (
    ChatPromptTemplate,
    PromptTemplate,
    SystemMessagePromptTemplate,
    AIMessagePromptTemplate,
    HumanMessagePromptTemplate
)
from langchain.output_parsers import StructuredOutputParser, ResponseSchema
from langchain.schema import (
    AIMessage,
    HumanMessage,
    SystemMessage
)
import re
SystemPrompt = PromptTemplate(
    template="You are a cybersecurity engineer, and your task is to analyze the provided code snippet and the potential vulnerability types to identify the function in the given code where the vulnerability is most likely to occur.",
)


HumanPromptStep2 = PromptTemplate(
    template="""
		    User question: Please analyze all functions in the code snippet I provided to determine whether they have potential authentication bypass vulnerabilities, and output the names of all functions and their total confidence (including functions with a total confidence of 0).

            <context> {code_context} </context>
            Answer the user's question using the information in <context>.

            Output format: {format_instructions}
            an example of output is:curly_brace"functions": [curly_brace "name": "daemonCheck","confidence": 10 end_curly_brace,curly_brace "name": "daemonControl","confidence": 30 end_curly_brace] end_curly_brace

            Analysis criteria: 
            1. Weak or missing authentication checks (20 points): Add 20 points if a function performs privileged operations or grants access without validating user credentials or session tokens. This includes cases where authentication logic is incomplete or entirely missing.
            2. Improper verification logic (20 points): Add 20 points for flawed logic in authentication processes, such as incorrect password/token validation, acceptance of partial/empty credentials, or overly permissive access control.
            3. Session management issues (20 points): Add 20 points if session handling lacks proper checks, including missing token validation, use of predictable or insecure session identifiers, or failure to invalidate sessions when appropriate (e.g., on logout).
            4. Backdoors or insecure fallback mechanisms (40 points): Add 40 points if the function contains mechanisms that bypass authentication, such as hardcoded credentials, debug modes, or any form of unrestricted access intended for testing or maintenance.

            [Attention!]:
            1. Total confidence of each function is the sum of points from the above criteria.
            2. Ensure that all functions in the code snippet are analyzed and included in the output.
            3. Pay particular attention to indirect influences, such as unchecked authentication states being passed to other functions.
            4. The output must be valid JSON.
            5. Avoid producing results where all functions have identical scores unless justified by the analysis. Provide meaningful differentiation based on potential vulnerabilities.
            
            Key Notes for AI:
            1. Focus on identifying risks specifically related to authentication bypass, not general issues.
            2. Use clear, concise language to explain the scoring and avoid unnecessary verbosity.
            3. Provide detailed reasoning for any function scoring zero, ensuring the logic is thorough and traceable.
        """,
    input_variables=["code_context"]
)

response_schemas_step2 = [
    ResponseSchema(name="functions", description="a list of function names with their respective confidence levels")

]
length_limit=14000

def check_output_regex(output):
    pattern = r"maximum context length is 8000 tokens"
    if re.search(pattern, output):
        return 1
    else:
        return 0
    
def llm_api_step2(prompt_code, key_env, base_env):
    global length_limit
    if len(prompt_code)>length_limit:
        prompt_code = prompt_code[:length_limit]
    llm = ChatOpenAI(
        streaming=True,
        verbose=True,
        # key和base开赛后提供
        openai_api_key=key_env,
        openai_api_base=base_env,
        model_name='tq-gpt',
        timeout=300
    )
    # create HumanMessagePromptTemplate
    HumanMessagePrompt = HumanMessagePromptTemplate(prompt=HumanPromptStep2)
    SystemMessagePrompt = SystemMessagePromptTemplate(prompt=SystemPrompt)
    # conbine Prompt
    chat_template = ChatPromptTemplate.from_messages([SystemMessagePrompt,HumanMessagePrompt])

    output_parser = StructuredOutputParser.from_response_schemas(response_schemas_step2)

    format_instructions = output_parser.get_format_instructions()
    #prompt = split_prompt(prompt, 6000)

    chain=LLMChain(llm=llm, prompt=chat_template)
    try:
        output = chain.run(code_context=prompt_code,format_instructions=format_instructions)
        print(output)
        json_out=output_parser.parse(output)
        # AI may regard a content to be None not NULL
        # Change later
        for i in range(10):
            if json_out["functions"]:
                break
            output = chain.run(code_context=prompt_code,format_instructions=format_instructions)
            #print(output)
            json_out=output_parser.parse(output)
        return json_out
    except Exception as e:
        print(f"Request timed out. {e}")
        if check_output_regex(str(e)) == 1:
            length_limit = length_limit - 2000
        return None
    
def check_bypass(prompt_code, key_env, base_env):
    global length_limit
    length_limit = 14000
    json_out=llm_api_step2(prompt_code, key_env, base_env)
    for i in range(50):
        if json_out is not None:
            break
        json_out=llm_api_step2(prompt_code, key_env, base_env)
    return json_out

# check by yourself
#filepath='a'
#with open(file_path, encoding='utf-8') as file:
#    file_content = file.read()
#json_out=check_arbitrary(file_content, "8bb73128d0b5732a1e0723f922245df8", 'https://poc.qianxin.com')
