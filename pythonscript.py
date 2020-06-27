import os
import socket
import subprocess
def run_pd_rpc(cmd_or_code, no_print=False):
    """
    This function invokes run_pd_rpc.py tool. It has a single string argument
    cmd_or_code that works as follows:
       If it is a string:
            * if the string starts with os.sep, then it is a filename
            * otherwise it is a piece of code (passed via "--eval"
       Else it is a list/tuple and it is passed "as-is"

    Note: do not attempt to run the tool in the interactive mode!
    """
    import subprocess
    path = os.path.join(os.environ['HOME'], "tools", "run_pd_rpc.py")
    
    command = [path]
    if isinstance(cmd_or_code, str):
        if cmd_or_code.startswith(os.sep):
            command.extend(["--no-wait", cmd_or_code])
        else:
            command.extend(["--no-wait", "--eval", cmd_or_code])
    else:
        command.extend(cmd_or_code)
        
    result = subprocess.check_output(command).decode("utf-8")[:-1]
    if not no_print:
        print(result)
        
    return result


HOST = '172.16.44.101'  # Standard loopback interface address (localhost)
PORT = 19876        # Port to listen on (non-privileged ports are > 1023)



with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(5)
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        data = conn.recv(1024)
        va   = int.from_bytes(data[0:8],byteorder='big')
        rkey = int.from_bytes(data[8:12],byteorder='big')
        qp   = int.from_bytes(data[12:16],byteorder='big')
        print(hex(qp), hex(va), hex(rkey))
        
        bfrt.port_copying.pipe.SwitchEgress.set_qp_vr_rk.add_with_set_qp_vr_rk_action(0x80, qp, va, rkey)
        conn.sendall(data)


    conn.close()

print("before")
run_pd_rpc("tm.set_cpuport(128);")
print("after")
