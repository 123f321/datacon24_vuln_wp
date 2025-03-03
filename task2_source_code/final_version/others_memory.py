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
HumanPromptStep2 = PromptTemplate(
    template="""
		User question:We will first provide you several examples starting with ###Examples### . Every example in it contains a vulnerability. You need to summary the reason why they are considered vulnerable.
    The Chinese explainations and function names in the examples are very important and do not lose information in it while summarizing.
    The history of our previous conversation will be saved in {history}.
    At last, If we give you some content starting with a symbol ###New Content###, we are giving you several new functions that may contain similar vulnerabilities.
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
"""
 to determine if any function contain the pattern I am interested.
        Let's analyze each function step by step based on the code I provide. We will consider each function independently and, based on the analysis criteria I give, assign a score named "confidence"(0-100)(only one function has the top score) to each function.:
        1.We are interested in function that direcly contains the patter I am intersted. For example if funcA calls funcB, funcB calls strcpy, and strcpy is in the list I am interested in, you should return funcB(high confidence). The confidence of both funcA and strcpy should be 0.
        2.Add 50 scores if a function directly contains function calls listed in {high_risk_functions}.
        3.Add 50 scores if a function directly contains some interested calls whose name is partly in {high_risk_functions}. For example, ios::strcpy is also a target because strcpy is in the list, stdin_scanf is also a target because scanf is in the list.
        4.If a function directly contains function calls listed in {low_risk_functions}, and the length parameter of the call(eg:the third parameter of strncpy) is not a const number, add 20 points to it.
        5.If the length parameter of step 2 comes from strlen(source buffer), add 20 points to it.
        For Example: c=strlen(b);strncpy(a,b,c)
        6.If a function directly contains a function call which is not in the above two lists but have similar pattern and have a symbol,(eg:json_load) do not regard it as an item in the above two list, regard it as a new type and add 10 points to it.
        7.If a function directly contains a type change from signed value into unsigned value and than passed the value into function calls listed in {low_risk_functions}, add 5 points to it.
        8.Please make sure that the output json is a legal json file and output your analysis process of each step.            

        <context>


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
examples="""
示例一：在函数sub_63D58中存在sql注入漏洞，通过`sprintf`拼接到token查询语句，执行`sqlite3_exec`实现sql注入
__int64 __fastcall sub_63D58(
        __int64 a1,
        const char *a2,
        int a3,
        _BYTE *a4,
        unsigned int a5,
        unsigned int a6,
        __int64 a7,
        __int64 a8,
        __int64 a9)
{
……
  v35 = sqlite3_mprintf("SELECT * FROM QTOKEN %s %s %s;", v36, v38, v37);
  v34 = sqlite3_open(a2, &v33);
  if ( v34 )
  {
    sqlite3_free(v35);
    sqlite3_free(v38);
    sqlite3_free(v37);
    v22 = (const char *)sqlite3_errmsg(v33);
    sub_62648("open %s failed! (%d, %s)\n", a2, v34, v22);
    return 4294967276LL;
  }
  else
  {
    sqlite3_busy_timeout(v33, 60000LL);
    v34 = sqlite3_exec(v33, v35, a1, a9, 0LL); //执行`sqlite3_exec`实现sql注入
……
}


示例二：在函数中SchemaHandleFunc中SSRF漏洞，
func (m *Mux) SchemaHandleFunc(c echo.Context) (err error) {
    if m.Disable {
        c.Response().WriteHeader(http.StatusForbidden)
        _, _ = c.Response().Write([]byte("schema is disabled"))
        return
    }

    r := c.Request()

    //  protocol:= r.Header.Get("X-InstanceProtocol")
    //  sslActive:=r.Header.Get("X-InstanceSSL")
    var (
        response   *http.Response
        req        *http.Request
        instanceIP = r.Header.Get("X-InstanceIP")
        requestUrl = strings.Replace(r.RequestURI, "testSchema/", "", 1)
        url        = "http://" + instanceIP + requestUrl
    )

    switch r.Method {
    case "GET":
        req, err = http.NewRequest(http.MethodGet, url, nil)
    case "POST":
        req, err = http.NewRequest(http.MethodPost, url, r.Body)
    case "PUT":
        req, err = http.NewRequest(http.MethodPut, url, r.Body)
    case "DELETE":
        req, err = http.NewRequest(http.MethodDelete, url, r.Body)
    default:
        c.String(http.StatusNotFound, "Method not found")
        return

    }

    if err != nil {
        c.String(http.StatusInternalServerError,
            fmt.Sprintf("( Error while creating request due to : %s", err))
        return
    }

    for key, values := range r.Header {
        for _, val := range values {
            if key == "Accept-Encoding" || key == "Connection" || key == "X-Schemaname" || key == "Cookie" || key == "User-Agent" || key == "AppleWebKit" || key == "Dnt" || key == "Referer" || key == "Accept-Language" {
                continue
            } else {
                req.Header.Add(key, val)
            }

        }
    }
    req.Header.Add("Content-Type", "application/json")
    client := http.Client{Timeout: time.Second * 20}
    response, err = client.Do(req)
    if err != nil {
        c.String(http.StatusNotFound,
            fmt.Sprintf("( Error while sending request due to : %s", err))
        return
    }
    respBody, err := ioutil.ReadAll(response.Body)
    if err != nil {
        c.String(http.StatusNotFound,
            fmt.Sprintf("(could not fetch response body for error %s", err))
        return
    }

    c.String(http.StatusOK, string(respBody))
    return nil
}   其中，req 网络请求的被输入到client.Do执行导致SSRF漏洞



示例三：函数qxl_cursor中存在double-fetch漏洞，函数中涉及多次对cursor的操作，先用cursor_alloc进行分配，再在后续对cursor->header.width, cursor->header.height进行处理，但是实际上cursor->header.width等变量可以被用户持有，并在分配到使用的时间间隙中被修改
```
static QEMUCursor *qxl_cursor(PCIQXLDevice *qxl, QXLCursor *cursor,
                              uint32_t group_id)
{
    QEMUCursor *c;
    uint8_t *and_mask, *xor_mask;
    size_t size;

    c = cursor_alloc(cursor->header.width, cursor->header.height);

    if (!c) {
        qxl_set_guest_bug(qxl, "%s: cursor %ux%u alloc error", __func__,
                cursor->header.width, cursor->header.height);
        goto fail;
    }

    c->hot_x = cursor->header.hot_spot_x;
    c->hot_y = cursor->header.hot_spot_y;
    switch (cursor->header.type) {
    case SPICE_CURSOR_TYPE_MONO:
        /* Assume that the full cursor is available in a single chunk. */
        size = 2 * cursor_get_mono_bpl(c) * c->height;
        if (size != cursor->data_size) {
            fprintf(stderr, "%s: bad monochrome cursor %ux%u with size %u\n",
                    __func__, c->width, c->height, cursor->data_size);
            goto fail;
        }
        and_mask = cursor->chunk.data;
        xor_mask = and_mask + cursor_get_mono_bpl(c) * c->height;
        cursor_set_mono(c, 0xffffff, 0x000000, xor_mask, 1, and_mask);
        if (qxl->debug > 2) {
            cursor_print_ascii_art(c, "qxl/mono");
        }
        break;
    case SPICE_CURSOR_TYPE_ALPHA:
        size = sizeof(uint32_t) * cursor->header.width * cursor->header.height; # cursor 是 guest 物理内存，直接读取可能受到竞争
        qxl_unpack_chunks(c->data, size, qxl, &cursor->chunk, group_id);
        if (qxl->debug > 2) {
            cursor_print_ascii_art(c, "qxl/alpha");
        }
        break;
    default:
        fprintf(stderr, "%s: not implemented: type %d\n",
                __func__, cursor->header.type);
        goto fail;
    }
    return c;

fail:
    cursor_put(c);
    return NULL;
}
```
对 guest 可控制的值 `cursor->header.width` 以及 `cursor->header.height` 的 double fetch 行为可能导致 heap-based buffer overflow.


示例四：函数varify中存在CSRF漏洞，该漏洞在处理用户提交的配置文件时，存在潜在的跨站请求伪造（CSRF）攻击。这个漏洞允许攻击者通过构造恶意请求来修改用户的配置文件，而不需要知道用户的认证信息。在`class UserPreference`的`varify()`中，具体触发流程包括：
1. 通过 `if("saveProfile".equals(request.getParameter("action")))` 条件判断是否执行保存配置文件的操作。
2. 调用 `userMgr.parseProfile(wikiContext)` 解析来自请求的用户配置文件数据。
3. 使用 `userMgr.validateProfile(wikiContext, profile)` 对解析后的配置文件进行验证。
4. 如果没有错误消息，调用 `userMgr.setUserProfile(wikiSession, profile)` 更新用户配置文件，并使用 `CookieAssertionLoginModule.setUserCookie(response, profile.getFullname())` 设置用户cookie。



示例五：函数sub_ACC670中存在格式化字符串漏洞
```C
int __fastcall sub_ACC670(__int64 a1, __int64 a2)
{
    //...

  v3 = sub_AE33A0(a2, "authip");
  if ( v3 || (v3 = sub_AE33A0(a2, "fmg_fqdn")) != 0 || (v3 = sub_AE33A0(a2, "mgmtip")) != 0 )
    snprintf((char *)(a1 + 204), 0x7FuLL, *(const char **)(v3 + 8));
    // ...
}
```
在函数`sub_ACC670`中获取传输的fmg_fqdn或mgmtip后作为格式化串，传入snprintf，存在格式化字符串漏洞


示例六：在函数URLLoader::NotifyCompleted中存在UAF漏洞
```C++
void URLLoader::SetUpUpload(const ResourceRequest& request,
                            int error_code,
                            std::vector<base::File> opened_files) {
  if (error_code != net::OK) {
    DCHECK(opened_files.empty());
    // Defer calling NotifyCompleted to make sure the URLLoader finishes
    // initializing before getting deleted.
    base::SequencedTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce(&URLLoader::NotifyCompleted,
                                  base::Unretained(this), error_code));
    return;
  }
  scoped_refptr<base::SequencedTaskRunner> task_runner =
      base::ThreadPool::CreateSequencedTaskRunner(
          {base::MayBlock(), base::TaskPriority::USER_VISIBLE});
  url_request_->set_upload(CreateUploadDataStream(
      request.request_body.get(), opened_files, task_runner.get()));
  if (request.enable_upload_progress) {
    upload_progress_tracker_ = std::make_unique<UploadProgressTracker>(
        FROM_HERE,
        base::BindRepeating(&URLLoader::SendUploadProgress,
                            base::Unretained(this)),
        url_request_.get());
  }
  BeginTrustTokenOperationIfNecessaryAndThenScheduleStart(request);
}
```
函数`URLLoader::SetUpUpload`中使用`BindOnce`绑定回调`URLLoader::NotifyCompleted`,传入了`base::Unretained(this)`，如果在任务执行前this被销毁，就会在`URLLoader::NotifyCompleted`时访问被释放的内存导致UAF

示例七：函数StorageService::GetLastFailedSaveLocationPath中存在race condition漏洞，具体原理为StorageService::GetLastFailedSaveLocationPath函数中在操作关键全局变量时没有进行锁保护，从而导致条件竞争，block可能在运行期间达到非预期结果，从而导致程序运行错误
__int64 __fastcall StorageService::GetLastFailedSaveLocationPath(StorageService *this, HLOCAL *a2)
{
  __int64 result; // rax
  __int64 v4; // rdi
  unsigned __int64 v5; // rdi
  HLOCAL v6; // rax
  unsigned int v7; // edi
  int v8; // [rsp+20h] [rbp-8h]
  wil::details::in1diag3 *retaddr; // [rsp+28h] [rbp+0h]

  if ( !a2 )
    return 2147942487i64;
  *a2 = 0i64;
  result = (__int64)Block;
  if ( Block )
  {
    v4 = -1i64;
    do
      ++v4;
    while ( Block[v4] );
    v5 = v4 + 1;
    v6 = LocalAlloc(0x40u, 2 * v5);
    *a2 = v6;
    if ( v6 )
    {
      v7 = StringCchCopyW((unsigned __int16 *)v6, v5, Block);
      free(Block);
      Block = 0i64;
      if ( v7 )
      {
        LocalFree(*a2);
        *a2 = 0i64;
      }
      return v7;
    }
    else
    {
      wil::details::in1diag3::Return_Hr(
        retaddr,
        (void *)0x171E,
        (unsigned int)"onecore\\drivers\\storage\\storsvc\\service\\storageservice.cpp",
        (const char *)0x8007000Ei64,
        v8);
      return 2147942414i64;
    }
  }
  return result;
}

Appendix: some possible function types
1.Double-Fetch issues involving multiple interactions with kernel functions, such as copy_from_user(), get_user(), copy_to_user() and put_user(), and if the function involve kernel malloc function like cursor_alloc and use malloc resource not at once, which must have a vulnerability.
2.SQL Injection: pay attention to dangerous functions like mysql_query(). If there are any, please focus on these points:(1)Direct SQL query construction;(2)Examine how user input is incorporated into SQL queries. and finally provide me with the function that is most likely to have an SQL injection vulnerability.
3.Race condition: Please focus on the following: (1)Checking resources before use, such as verifying file paths or structure head before using functions like open() to operate on files.(2)Improper use of locking functions that can lead to vulnerabilities. and finally provide me with the function that is most likely to have an race condition vulnerability.
4.Use-after-free:focus on the situation where resources are released before being used. Please pay special attention to functions related to resource release and allocation that are associated with Use-After-Free (UAF), such as free() and malloc(). and finally provide me with the function that is most likely to have an UAF vulnerability.
5.format string: occurs when an application uses user-supplied input as the format string parameter in formatting functions like printf(), fprintf(), sprintf(), etc., without proper validation or sanitization. , provide me with the function that is most likely to have an format string vulnerability.
6.CSRF and SSRF:pay attention to High-Risk Functions and Methods like (HTML rendering functions), (JavaScript generation) or (manipulation and DOM manipulation methods), if have any CSRF vulnerability, provide me with the function that is most likely to have an CSRF vulnerability.
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
    
def check_others(prompt_code, key_env, base_env):
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
