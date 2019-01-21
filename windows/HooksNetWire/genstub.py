import sys

# ex stdin:
# 
# SOCKET WSAAPI socket(
#     int af,
#     int type,
#     int protocol
# )
pattern = """
&&&_INTEST_&&&
{
&&&_INIT_&&&
    Message("&&&_NAME_&&& called by 0x%x.\\n", _ReturnAddress());
#if S2E
&&&_S2E_&&&
#else
&&&_NO_S2E_&&&
#endif

&&&_END_&&&
    Message("  [&&&_NAME_&&&] ret: 0\\n");
    return 0;
}
"""

pattern_no_pointer_s2e = """
    if (S2EIsSymbolic(&&&&_VAR_&&&, 1))
        S2EPrintExpression((UINT_PTR)&&&_VAR_&&&, "[&&&_NAME_&&&] &&&_PAR_N_&&&: ");
    else
        Message("  [&&&_NAME_&&&] &&&_PAR_N_&&&: 0x%x\\n", &&&_VAR_&&&);"""

pattern_string_s2e = """
    if (S2EIsSymbolic(&&&&_VAR_&&&, 1))
        S2EPrintExpression((UINT_PTR)&&&_VAR_&&&, "[&&&_NAME_&&&] &&&_PAR_N_&&&: ");
    else {
        Message("  [&&&_NAME_&&&] &&&_PAR_N_&&&: 0x%x\\n",  &&&_VAR_&&&);
        if (S2EIsSymbolic((PVOID)&&&_VAR_&&&, 1))
            S2EPrintExpression((UINT_PTR)*((char*)&&&_VAR_&&&), "[&&&_NAME_&&&] *&&&_PAR_N_&&&: ");
        else
            Message("  [&&&_NAME_&&&] *&&&_PAR_N_&&&: %s\\n",  &&&_VAR_&&&);
    }"""

pattern_buffer_s2e = """
    if (S2EIsSymbolic(&&&&_VAR_&&&, 1))
        S2EPrintExpression((UINT_PTR)&&&_VAR_&&&, "[&&&_NAME_&&&] &&&_PAR_N_&&&: ");
    else {
        Message("  [&&&_NAME_&&&] &&&_PAR_N_&&&: 0x%x\\n",  &&&_VAR_&&&);
        if (S2EIsSymbolic((PVOID)&&&_VAR_&&&, 1))
            S2EPrintExpression((UINT_PTR)*((char*)&&&_VAR_&&&), "[&&&_NAME_&&&] *&&&_PAR_N_&&&: ");
        else {
            hex_&&&_VAR_&&& = data_to_hex_string((char*)&&&_VAR_&&&, sizeof(&&&_VAR_&&&));
            Message("  [&&&_NAME_&&&] *&&&_PAR_N_&&&: %s\\n",  hex_&&&_VAR_&&&);
        }
    }"""

pattern_no_pointer = """
    Message("  [&&&_NAME_&&&] &&&_PAR_N_&&&: 0x%x\\n", &&&_VAR_&&&);"""

pattern_string = """
    Message("  [&&&_NAME_&&&] &&&_PAR_N_&&&: 0x%x\\n",  &&&_VAR_&&&);
    Message("  [&&&_NAME_&&&] *&&&_PAR_N_&&&: %s\\n",  &&&_VAR_&&&);"""

pattern_buffer = """
    Message("  [&&&_NAME_&&&] &&&_PAR_N_&&&: 0x%x\\n",  &&&_VAR_&&&);
    hex_&&&_VAR_&&& = data_to_hex_string((char*)&&&_VAR_&&&, sizeof(&&&_VAR_&&&));
    Message("  [&&&_NAME_&&&] *&&&_PAR_N_&&&: %s\\n",  hex_&&&_VAR_&&&);"""

def no_pointer_s2e(var, name, par_id):
    return pattern_no_pointer_s2e.replace("&&&_VAR_&&&", var).replace("&&&_NAME_&&&", name).replace("&&&_PAR_N_&&&", par_id)
def string_s2e(var, name, par_id):
    return pattern_string_s2e.replace("&&&_VAR_&&&", var).replace("&&&_NAME_&&&", name).replace("&&&_PAR_N_&&&", par_id)
def buffer_s2e(var, name, par_id):
    return pattern_buffer_s2e.replace("&&&_VAR_&&&", var).replace("&&&_NAME_&&&", name).replace("&&&_PAR_N_&&&", par_id)
def no_pointer_no_s2e(var, name, par_id):
    return pattern_no_pointer.replace("&&&_VAR_&&&", var).replace("&&&_NAME_&&&", name).replace("&&&_PAR_N_&&&", par_id)
def string_no_s2e(var, name, par_id):
    return pattern_string.replace("&&&_VAR_&&&", var).replace("&&&_NAME_&&&", name).replace("&&&_PAR_N_&&&", par_id)
def buffer_no_s2e(var, name, par_id):
    return pattern_buffer.replace("&&&_VAR_&&&", var).replace("&&&_NAME_&&&", name).replace("&&&_PAR_N_&&&", par_id)

input_str = sys.stdin.read()
intest = input_str.strip()
input_str = filter(lambda x:x, input_str.split("\n"))
name = input_str[0].split(" ")[-1][:-1]
pars = []
i = 1
while input_str[i].find(")") == -1:
    curr = filter(lambda x:x, input_str[i].replace("\t", "    ").split(" "))
    t = reduce(lambda x, y: x+y, curr[:-1])
    n = filter(lambda x: x!=",", curr[-1])
    pars.append( ( t , t.find("LP")==0 or t.find("P")==0 or "*" in n , filter(lambda x: x!="*", n) ) )
    i+=1

init = ""
s2e = ""
no_s2e = ""
end = ""

frees = []

i = 0
for t, b, n in pars:
    if not b:
        s2e += no_pointer_s2e(n, name, str(i))
        no_s2e += no_pointer_no_s2e(n, name, str(i))
    if b and "STR" in t:
        s2e += string_s2e(n, name, str(i))
        no_s2e += string_no_s2e(n, name, str(i))
    if b and "STR" not in t:
        s2e += buffer_s2e(n, name, str(i))
        no_s2e += buffer_no_s2e(n, name, str(i))
        frees.append("hex_"+n)
    i+=1

for f in frees:
    init += "    char* %s = NULL;\n" % f
    end  += "    free(%s);\n" % f

ris = pattern.replace("&&&_INIT_&&&", init).replace("&&&_INTEST_&&&", intest).replace("&&&_S2E_&&&", s2e) \
             .replace("&&&_NO_S2E_&&&", no_s2e).replace("&&&_END_&&&", end).replace("&&&_NAME_&&&", name)
print ris
