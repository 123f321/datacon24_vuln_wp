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
		User question:Please analyze the provided specific code of a series of functions to determine if any of these functions contain potential Command injection vulnerabilities ,Your analysis must consider:
		User Input Flow: Analyze how user input flows into command execution functions like system(). Look for cases where input affects the commands being executed.
		Sanitization: Check if user input is validated for malicious patterns like ;, &&, ||, |, $(), backticks, or other special characters.
		Let's analyze each function step by step based on the code I provide. We will consider each function independently and, based on the analysis criteria I give, assign a confidence score (confidence score:s 1~10) to each function:
                1.Determine the Use of Command Execution Functions like system(), exec(), popen(), Runtime.exec(), ProcessBuilder, etc. If such functions are present, add 10 points to the confidence level.
                2.Unvalidated User Input: if user input directly influences command execution without validation, add 20 points to the confidence level.
                3.Consider Permission operations: if giving function exists any operation on Permission like $permission, which may influnecethe the command injection function Input, add 20 points to the confidence level.
                4.Use of Shell Metacharacters: Direct concatenation allows inclusion of shell metacharacters in inputs, add 20 points to the confidence level.
                5.If the function contains strings related to RCE such as "smb" or "/bin/sh", add 30 extra points to the confidence score. 
	
                <context>
                {code_context}
                </context>
                answer user's question with the information in <context>
                output format: {format_instructions}
                an example of output is:curly_brace"functions": [curly_brace "name": "daemonCheck","confidence": 10 end_curly_brace,curly_brace "name": "daemonControl","confidence": 30 end_curly_brace] end_curly_brace

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
            if json_out["functions"] or json_out["functions"]==[]:
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
    
def check_command(prompt_code, key_env, base_env):
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
