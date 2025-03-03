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

            <context>
            {code_context}
            </context>

            Answer the user's question using the information in <context>.  

            **Output format**: {format_instructions}  
            an example of output is:curly_brace"functions": [curly_brace "name": "daemonCheck","confidence": 10 end_curly_brace,curly_brace "name": "daemonControl","confidence": 30 end_curly_brace] end_curly_brace

            **Analysis criteria**:  
            1. **Input-controlled integers (10 points)**: Add 10 points if integers directly or indirectly influenced by user input or external data are used in critical logic, calculations, or resource operations without proper validation (e.g., range, format, or type checking).  
            2. **Lack of bounds checking (10 points)**: Add 10 points if integers influenced by user input or external data are used in array indexing, loop boundaries, or conditional checks without verifying their validity, which may lead to risks like out-of-bounds access or security bypass.  
            3. **Unsafe arithmetic (20 points)**: Add 20 points if arithmetic operations (e.g., addition, subtraction, multiplication) or type conversions involving user-controlled integers may result in overflow, truncation, or unexpected behavior.  
            4. **Memory or buffer allocation issues (40 points)**: Add 40 points if integers influenced by user input or external data are used for memory allocation, buffer operations, or size calculations without strict validation, posing risks like overflow or memory corruption.  

            [Attention!]:  
            1. Total confidence of each function is the sum of points from the above criteria.
            2. Analyze **all functions** in the provided code snippet and ensure no function is omitted.  
            3. Pay particular attention to **indirect influences** where integers are passed through intermediate variables or functions.  
            4. The output must be valid JSON. 
            5. Try not to output results with a total confidence of all 0, or all the same results, which will bother me.
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
