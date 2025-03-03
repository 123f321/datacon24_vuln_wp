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
from langchain.memory import ConversationSummaryMemory 
import re
SystemPrompt = PromptTemplate(
    template="You are a cybersecurity engineer, you know both English and Chinese, and you are an expert in static code analysis and can fully understand dataflow and definitions of common used functions in decompiled pseudocode, C, C++, java, python, go, js, and other similar languages.",
)

high_risky_functions="strcpy;strcat;sprintf;gets;scanf;sscanf;fscanf;vscanf;malloc;calloc;realloc;bcopy;fmt.Scanln;fmt.Fscanf;fmt.Scan;unsafe.Pointer"
low_risky_functions="strncpy;strncat;snprintf;fgets;memcpy;memmove;memset;bytes.Buffer.WriteString"
HumanPromptStep2 = PromptTemplate(
    template="""
		User question:We will first provide you several examples starting with ###Examples### . Every example in it contains a buffer overflow vulnerability. You need to summary the reason why they are considered vulnerable.
    The Chinese explainations and function names in the examples are very important and do not lose information in it while summarizing.
    The history of our previous conversation will be saved in {history}.
    At last, If we give you some content starting with a symbol ###New Content###, we are giving you several new functions that may contain similar buffer overflow vulnerabilities.
    In that case, you should analyse each function independently and output a most vulnerable function. You should first repeat the previous history information word by word, and then use confidence(0-100) to measure how vulnerable each function is, only one function should have the highest confidence.
    If the new content mentioned a function who have exactly the same name with one example function,that example function should have the highest confidence, and confidence of all other functions should be 0.
    If all functions in ###New Content### are not vulnerable, their confidence should all be 0.
    The content given to use are in <content>, the content is either a example(only need to summary) or a new content(need to output confidence of each function and previous history), it won't contain both types
    <context>
    {code_context}
    </context>
    output format: a legal json file such as {{"functions": [{{"name": "checkLoginUser","confidence": 0}},{{"name": "aaa","confidence": 10}}],"summary":"contains strcpy"}} and some additional information such as previous history.
            """,
    input_variables=["code_context"]
)

examples="""
示例1：在parse_object这个函数中，解析key的时候发生了溢出
_isoc99_sscanf(key, "%s %s", v9, v10);      // stack-based buffer overflow

示例2：在`do_SOCKS5` 函数中，memcpy的长度限制参数tlen由源缓冲区cp决定，因此源缓冲区很大时也可不受限制地拷贝入目标缓冲区，导致溢出
```c
static CURLproxycode do_SOCKS5(struct Curl_cfilter *cf,
                               struct socks_state *sx,
                               struct Curl_easy *data)
......
            if ( cp )
            {
              tlen = tlen[4];
              v64 = 1;
              opt = 0;
              while ( tlen )
              {
                if ( optlen < tlen )
                  break;
                memcpy(&v65[opt], cp + v64, tlen);
                v15 = &tlen[v64];
                if ( &tlen[v64] >= optlen )
                  break;
                v16 = &tlen[opt];
                v64 = (v15 + 1);
                tlen = v15[cp];//tlen is from  v15[cp]
                opt = (v16 + 1);
                v16[v65] = 46;
              }
            }
          }
        }

```

示例3：sub_408B70有直接溢出风险，sub_40DAC8中没有。
在 `sub_408B70` 函数中

```C
 if ( !a2 || a3 < *(_DWORD *)(a1[43] + 236) )
    return -1;
  memset(a2, 0, a3);
  v5 = (_DWORD *)a1[43];
  v6 = v5[3];
  v7 = v5[2] - v6;
  memcpy(a2, (const void *)(*v5 + v6), v7);
  result = v7;

```

使用 `a1[43][2] - a1[43][3]` 作为长度拷贝数据到缓冲区 a2 中，a2 在函数 `sub_40DAC8` 中分配

```C
  v7 = (_DWORD *)a1[43];
  ...
      v46 = (char *)j_malloc(v7[59] + 1);
      v47 = v46;
      if ( !v46 )
      {
        v48 = getpid();
        printf("[HTTPD (%d)]:: ", v48);
        printf(
          "::%.80s line::%d::%d::Cannot allocate memory for read_post_param (len=%d)\n",
          "do_ccp",
          344,
          *(_DWORD *)(a1[43] + 236) + 1);
LABEL_82:
        if ( v5 )
          e_free(v5);
        return 1;
      }
      if ( (sub_408B70(a1, v46, *(_DWORD *)(a1[43] + 236) + 1) & 0x80000000) != 0 )
```

然而分配的大小是 `a1[43][59] + 1`，这里存在的不一致会导致缓冲区溢出。

事实上 `a1[43][59] + 1` 是 Content-Length 指定的大小，`a1[43][2] - a1[43][3]` 是实际读到的 body 大小。

示例4：
在`sub_2A28` 函数中

```C
  size_t v2; // r0
  char v5[2048]; // [sp+10h] [bp-101Ch] BYREF
  char v6[2048]; // [sp+810h] [bp-81Ch] BYREF
  size_t n; // [sp+1010h] [bp-1Ch]
  char *s; // [sp+1014h] [bp-18h]

  memset(v6, 0, sizeof(v6));
  memset(v5, 0, sizeof(v5));
  s = strchr(**(const char ***)(a2 + 264), 63);
  if ( s )
  {
    v2 = strlen(s);
    buffer_copy_string_len(*(_DWORD *)(a2 + 708), s + 1, v2 - 1);
    n = (size_t)&s[-**(_DWORD **)(a2 + 264)];
    strncpy(v5, **(const char ***)(a2 + 264), n);
  }
```
先取出a2+264（也就是uri）中"?"后面的字符串，然后拼接到v5中，strncpy的长度限制参数n来自于源缓冲区长度 (size_t)&s[-**(_DWORD **)(a2 + 264)]，限制不生效，v5的长度固定为2048 byte，会造成溢出

示例5：
在`sub_41D354` 函数中

```C
        else if ( !strcmp(v25, "cookie") )
        {
          v11 = 0;
          v35 = 0;
          a1[62] |= 8u;
          a1[54] = sub_4036C4(v24);
          memset(&unk_589AF8, 0, 500);
          v5 = strlen(a1[54]);
          memcpy((int)&unk_589AF8, a1[54], v5);
          if ( !strcmp(&unk_589AF8, "uid=") )

```

memcpy 的长度参数v5直接来源于源缓冲区的长度strlen(a1[54])，因此源缓冲区很大时也可不受限制地拷贝入目标缓冲区，造成溢出

示例6：NpTranslateContainerLocalAlias函数中，堆分配函数的长度参数被转换为unsigned，可以整数溢出得到很大的值，这种转换成unsigned的值作为缓冲区分配或拷贝函数的长度参数时很容易溢出
v22 = (unsigned __int16)(v19 + v21); // 整数溢出
  v27.MaximumLength = v22;
  Pool2 = (WCHAR *)ExAllocatePool2(256i64, v22, 1850110030i64);// 堆溢出

示例7：
在 `ej_get_web_page_name` 函数中

```C
  char v8[48]; // [sp+18h] [-3Ch] BYREF
  ... ...
    else
    {
      memset(v8, 0, sizeof(v8));
      cgi = (const char *)get_cgi("submit_button");
      if ( !cgi )
        cgi = "index";
      sprintf(v8, "%s", cgi);
      if ( !strcasecmp(v8, "SSG") )
      {
        v5 = wfprintf(a2, "hset.htm");
        goto LABEL_6;
      }
      v3 = v8;
```

这一段代码可以将任意长度的字符串写入 v8，导致缓冲区溢出。

示例8：Dot11Translate80211ToEthernetNdisPacket函数可能存在整数溢出导致的缓冲区溢出问题

示例9：
在`connection_state_machine` 函数中

```C
    strcpy(needle, "asus_token");
    memset(&needle[11], 0, 0x15u);
    element = array_get_element(a2[76], "Cookie");
    if ( element )
    {
        v20 = buffer_init();
        buffer_copy_string_len(v20, **(_DWORD **)(element + 32), *(_DWORD *)(*(_DWORD *)(element + 32) + 4));
        buffer_urldecode_path(v20);
        memset(v14, 0, sizeof(v14));
        strncpy(v14, *(const char **)v20, *(_DWORD *)(v20 + 4));
        buffer_free(v20);
        haystack = v14;
        while ( 1 )
        {
        haystack = strstr(haystack, needle);
        if ( !haystack )

```
先获取cookie的值，`buffer_init()`会固定申请0xC的空间，然后直接使用stncpy拼接cookie的值，长度限制参数 *(_DWORD *)(v20 + 4)是变量而非常量，造成栈溢出

示例10：

在 `getSafariVersion` 函数中

```C
  char dest[44]; // [esp+10h] [ebp-3Ch] BYREF

  v4 = 0;
  if ( strstr(a1, "Safari") && !strstr(a1, "Chrome") )
  {
    v6 = strstr(a1, "Version/") + 8;
    v7 = strchr(v6, ' ');
    if ( v7 )
    {
      for ( i = 0; i < 0x20; i += 4 )
        *(_DWORD *)&dest[i] = 0;
      memcpy(dest, v6, v7 - v6);
```

这一段函数会将 UA 中 "Version/" 后直到空格之间的内容都复制到栈缓冲区上，且长度限制v7 - v6为变量而非常量，容易失效。由于该缓冲区长度只有 44 字节，因此存在溢出。
"""
response_schemas_step2 = [
    ResponseSchema(name="functions", description="a list of function names with their respective confidence levels"),
    ResponseSchema(name="summary", description="the summary of your judging reason")

]
memory=None

length_limit=14000

def check_output_regex(output):
    pattern = r"maximum context length is 8000 tokens"
    if re.search(pattern, output):
        return 1
    else:
        return 0

def llm_api_step2(prompt_code, key_env, base_env):
    global memory
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
        timeout=30
    )
    # create HumanMessagePromptTemplate
    HumanMessagePrompt = HumanMessagePromptTemplate(prompt=HumanPromptStep2)
    SystemMessagePrompt = SystemMessagePromptTemplate(prompt=SystemPrompt)
    # conbine Prompt
    chat_template = ChatPromptTemplate.from_messages([SystemMessagePrompt,HumanMessagePrompt])

    output_parser = StructuredOutputParser.from_response_schemas(response_schemas_step2)
    if memory==None:
        memory = ConversationSummaryMemory(llm=llm)
    format_instructions = output_parser.get_format_instructions()
    #prompt = split_prompt(prompt, 6000)
    
    chain=LLMChain(llm=llm, prompt=chat_template, memory=memory)
    try:
        output = chain.run(code_context=prompt_code)
        #print(output)
        json_out=output_parser.parse(output)
        # AI may regard a content to be None not NULL
        # Change later
        for i in range(10):
            if json_out["functions"]:
                break
            output = chain.run(code_context=prompt_code)
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
    global memory
    memory= None
    length_limit = 14000
    sample=examples
    json_out=llm_api_step2("###Examples###"+sample, key_env, base_env)
    for i in range(50):
        if json_out is not None:
            break
        json_out=llm_api_step2("###Examples###"+sample, key_env, base_env)
    json_out=llm_api_step2("###New Content###"+prompt_code, key_env, base_env)
    for i in range(50):
        if json_out is not None:
            break
        json_out=llm_api_step2("###New Content###"+prompt_code, key_env, base_env)
    return json_out
