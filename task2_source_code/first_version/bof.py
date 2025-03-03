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
    template="You are a cybersecurity engineer, you understand and are familiar with various languages including but not limited to decompiled pseudocode, C, C++, java, python, go, js, and you are an Expert in buffer overflow vulnerability analysis. Your task is to analyze the provided code snippet to identify the function in the given code where the vulnerability is most likely to occur.",
)

high_risky_functions="strcpy;strcat;sprintf;gets;scanf;sscanf;fscanf;vscanf;malloc;calloc;realloc;bcopy;fmt.Scanln;fmt.Fscanf;fmt.Scan;unsafe.Pointer"
low_risky_functions="strncpy;strncat;snprintf;fgets;memcpy;memmove;memset;bytes.Buffer.WriteString"
HumanPromptStep2 = PromptTemplate(
    template="""
		User question:Please analyze the provided specific code to determine if any function contain potential Buffer Overflow vulnerabilities, and provide a confidence score for your assessment. Buffer overflow vulnerability catagories includes:
		Dangerous buffer Options: Unsafe buffer operations such as strcpy, strcat, memmove, sprintf, etc.;
        Unsafe Stdin Read: Reading the content from stdin to a buffer(eg:gets, sscanf, etc. can read stdin as source buffer and copy its content into target buffer);
        Format String Processing: Reading string content through %s format[eg: sprintf(a,"%s",b)];
		Array Boundaries: operations that access array elements out of bounds. For instance, any array index accesses that exceed the declared size of the array(usually occur in loops);
        Heap vulnerabilities: buffer operations relevant to heap operations, such as memcpy and memmove;
        Type Confusion: places where data might be treated as a different type and then bypass some length checks.[such as type confusion and interger overflow, consider an length limit len_a<10 with len_a=-1 and then use it as unsigned int in snprintf(a,b,(unsigned int)len_a)];
        
        Sanitization: If the following length check sanitizations occurs, the operation are usually no longer vulnerable:
        Safe buffer operations: Some operation contains length checks such as strncpy, strncat, snprintf, etc. This will make an operation nearly not vulnerable unless the check has been bypassed.(eg: fixed length check parameter "20" in strncpy(a,b,20) and similiar functions are very strict length checks)
        Dynamic target buffer: Some target buffer are dynamically created by heap operations and will never be smaller than the source buffer or the length limit.[eg:a=malloc(strlen(b));strcpy(a,b)]
        Checked source buffer: Some source buffer has been length checked [eg: char a[10];if len(b) < 10 then strcpy(a,b) is not vulnerable because the if statement checked source buffer b to be smaller than 10];
        Buffer length limitations: Any buffer copy whose length is smaller than the definition of the target buffer is not vulnerable anymore.(For example, in the code char a[20], strncpy(a, b, 20), length check is "20" and the definition of the buffer size is also 20, so it won't overflow)
)

        <context>
        {code_context}
        </context>
        answer user's question with the information in <context>
        output format: {format_instructions}
        an example of output is:curly_brace"functions": [curly_brace "name": "daemonCheck","confidence": 10 end_curly_brace,curly_brace "name": "daemonControl","confidence": 30 end_curly_brace] end_curly_brace

        Let's analyze each function step by step based on the code I provide. We will consider each function independently and, based on the analysis criteria I give, assign a confidence score(0-10)(only one function has the top score) to each function.:
        1.When calculating confidence, first, consider each buffer overflow vulnerability catagory and other similar catagories that is not metioned. Consider the vulnerability exist if an operation is not diretly in a type but is highly relevant to it;
        2.If the function contains dangerous operations listed in {high_risk_functions}, these functions have no length checks so the confidence score should be higher than 7.
        3.If a length check of memcpy is just strlen of the source buffer, the length check has no use and the confidence should still be greater than 7 [eg:memcpy(a,b,strlen(b)), this operation may be seperated into several operations];
        4.Some dangerous operations are listed in {low_risk_functions}, these functions have length check parameters so th confidence score should be less than 6.
        5.Functions with similar names and patterns but not in the above two lists or other vulnerable operations not listed in the list should have confidence less than 4.
        6.Consider the three sanitization types, consider dataflow between functions to check source buffer sanitization, the confidence score of the operation with sanitizations must be lower than those without sanitizations;
        7.Consider bypass of sanitizations, if there is a bypass of length checks, the confidence should be higher than those without bypass, but should still be lower than those operations without sanitizations.
        8.If the risk come from a function without symbol information, it is no longer considered as a vulnerability and should have a very low score.[eg: sub_a(str1,str2) might be a dangerous buffer operation function, but there are no symbol that ensure its vulnerability, so the confidence is very low]
        9.The confidence of the function is the same as the highest confidence of an dangerous operation in it.(highest, not sum, if operation1 has score 2, operation2 has score 3, funtion confidence is 3)
        10.Be careful with hex, the code given to you is very likely to be some decompiled procedures.(eg:0x10 is equal to 16 and may be a strict length check sanitization).
        11.Please make sure that the output json is a legal json file and output your analysis process of each step, recheck if an answer contradicts criterias 1-10.            

            """,
    input_variables=["code_context","high_risk_functions","low_risk_functions"]
)
"""
2.Add 90 points if there are some stdin input such as gets or webgetvar(always assume stdin input to be very large) and this input parsed into a buffer without length check.
        3.Add 90 points if there is vulnerable buffer operation without any length check before it, such as the use of strcpy or sscanf without checking the target buffer size.
        4.Add 60 points if there is a high likelihood of a buffer overflow, there are some length checks, but the check may be bypassed and the source buffer can still be bigger than the target buffer.
        5.Add 40 points if there it can not match step 2-4, but there may still be hidden risks.
        6.Minus 30 points if the lengths used in an operation does not exceed the buffer size definition. Check source buffer definition and operation length check carefully.
            For example, in the code char a[20]; strncpy(a, b, 20);, verify whether the length check (20) could cause an overflow based on the buffer size (also 20, won't overflow)
        7.Minus 20 points if the risk come from a function without symbol information.(eg: sub_a(str1,str2) might be a dangerous buffer operation function, but there are no symbol that ensure its vulnerability)
        8.Recheck the length limitations of the buffer overflow dangerous operation, consider dataflow cross functions, assume the length of the target buffer and the max length of the source buffer, minus 40 points(no less than 0) if the check suggest that source buffer won't be longer than target buffer.
        9.Add 50 point if there is a bypass of length limitation.
"""
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
        output = chain.run(code_context=prompt_code,format_instructions=format_instructions,high_risk_functions=high_risky_functions,low_risk_functions=low_risky_functions)
        print(output)
        json_out=output_parser.parse(output)
        # AI may regard a content to be None not NULL
        # Change later
        for i in range(10):
            if json_out["functions"]:
                break
            output = chain.run(code_context=prompt_code,format_instructions=format_instructions,high_risk_functions=high_risky_functions,low_risk_functions=low_risky_functions)
            #print(output)
            json_out=output_parser.parse(output)
        return json_out
    except Exception as e:
        print(f"Request timed out. {e}")
        if check_output_regex(str(e)) == 1:
            length_limit = length_limit - 2000
        return None
    
def check_bof(prompt_code, key_env, base_env):
    global length_limit
    length_limit = 14000
    json_out=llm_api_step2(prompt_code, key_env, base_env)
    for i in range(50):
        if json_out is not None:
            break
        json_out=llm_api_step2(prompt_code, key_env, base_env)
    return json_out

