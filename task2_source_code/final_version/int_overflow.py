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
		    User question: Please analyze all functions in the code snippet I provided to determine whether they have potential integer overflow vulnerabilities, and output the names of all functions and their total confidence (including functions with a total confidence of 0).

            <context> {code_context} </context>
            Answer the user's question using the information in <context>.

            Output format: {format_instructions}

            Analysis criteria:
            1. Input-controlled integers (10 points): Add 10 points if integers influenced directly or indirectly by user input or external data are used in operations or logic without proper validation (e.g., checking range, format, or type).
            2. Lack of bounds checking (10 points): Add 10 points if integers influenced by user input or external data are used in contexts like array indexing, loop boundaries, or conditions without verifying their validity, potentially causing out-of-bounds access or incorrect execution.
            3. Unsafe arithmetic (20 points): Add 20 points for arithmetic operations (e.g., addition, subtraction, multiplication) or type conversions involving user-controlled integers that may lead to overflow, truncation, or unexpected results.
            4. Memory or buffer allocation issues (40 points): Add 40 points if integers influenced by user input or external data are used for memory allocation, buffer manipulation, or size calculations without sufficient validation, creating risks like memory corruption or denial of service.

            [!!!Attention!!!]:
            1. The total confidence for each function is the cumulative score of all criteria.
            2. Analyze every function in the provided code snippet without omission.
            3. Pay special attention to indirect impacts where user input affects integers through intermediate variables or function calls.
            4. Ensure the output is valid JSON and clearly identifies potential vulnerabilities.
            5. Ensure only one function has the highest confidence score, and avoid giving identical scores to all functions(In particular, do not output all 0s or all highest scores).
            
            Key Notes for AI:
            1. Focus on detecting user-controlled or externally influenced integers that contribute to potential overflow scenarios.
            2. Be concise but thorough in your reasoning for each score, particularly for functions scored 0.
            3. Highlight specific vulnerabilities related to integer misuse rather than generic code issues.
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
        #print(output)
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
    
def check_int_overflow(prompt_code, key_env, base_env):
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
