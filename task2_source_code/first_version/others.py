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
		User question:Please analyze the provided specific code of a series of functions to determine if any of these functions contain potential vulnerabilities, I will provide you with several types of vulnerabilities, as well as key dangerous functions or patterns that lead to these vulnerabilities for your consideration. Please identify the specific function that contains the vulnerability trigger point. Note that there will be only one function with the vulnerability trigger point. Please think carefully, analyze step by step, and ultimately return to me the specific name of the vulnerable function, as well as the type of vulnerability:
		here are the potential types of the vulnerability:
		1.SQL Injection: pay attention to dangerous functions like mysql_query(). If there are any, please focus on these points:(1)Direct SQL query construction;(2)Examine how user input is incorporated into SQL queries. and finally provide me with the function that is most likely to have an SQL injection vulnerability.
		2.Race condition: Please focus on the following: (1)Checking resources before use, such as verifying file paths before using functions like open() to operate on files.(2)Improper use of locking functions that can lead to vulnerabilities. and finally provide me with the function that is most likely to have an race condition vulnerability.
		3.Use-after-free:focus on the situation where resources are released before being used. Please pay special attention to functions related to resource release and allocation that are associated with Use-After-Free (UAF), such as free() and malloc(). and finally provide me with the function that is most likely to have an UAF vulnerability.
		4.format string:focus on dangerous function like printf(),scanf() etc. Further determine whether the input to these dangerous functions can be controlled by user input, and if so, provide me with the function that is most likely to have an format string vulnerability.
		5.CSRF and SSRF:pay attention to High-Risk Functions and Methods like (HTML rendering functions), (JavaScript generation) or (manipulation and DOM manipulation methods), if have any CSRF vulnerability, provide me with the function that is most likely to have an CSRF vulnerability.
		6.Double-Fetch issues involving multiple interactions with kernel functions, such as copy_from_user(), get_user(), copy_to_user() and put_user(), If a function contains two calls to the aforementioned interaction functions that both operate on the same kernel object, please output the name of the involved function, which must have a vulnerability.
		Finally, If none of the aforementioned types of vulnerabilities are present, do not output any results. 
	
                <context>
                {code_context}
                </context>
                answer user's question with the information in <context>
                output format: {format_instructions}
            """,
    input_variables=["code_context"]
)

response_schemas_step2 = [
    ResponseSchema(name="functions", description="function name"),
    ResponseSchema(name="types", description="The specific type of vulnerability"),
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
    
def check_others(prompt_code, key_env, base_env):
    global length_limit
    length_limit = 14000
    json_out=llm_api_step2(prompt_code, key_env, base_env)
    for i in range(50):
        if json_out is not None:
            break
        json_out=llm_api_step2(prompt_code, key_env, base_env)
    pattern = r'\)\s+(\w+)\s*\('

    # Search for the pattern in the code string
    match = re.search(pattern, json_out["functions"])

    if match:
    # Extract the function name
        json_out["functions"] = match.group(1)
    json_out["functions"]=[json_out["functions"]]
    json_out["confidence"]=100
    return json_out

# check by yourself
#filepath='a'
#with open(file_path, encoding='utf-8') as file:
#    file_content = file.read()

#json_out=check_arbitrary(file_content, "8bb73128d0b5732a1e0723f922245df8", 'https://poc.qianxin.com')
#print(json_out)
