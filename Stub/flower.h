#pragma once
#define _DEMONS_USED_FLOWER  //此开关控制编译器是否使用花指令
#ifndef _DEMONS_USED_FLOWER
#define __FLOWER_DEMONS1	_asm nop
#define __FLOWER_DEMONS2	_asm nop
// rdword：随意填写一个16字节数字，但不要太大
// norun：一段指令，永远不会被执行，之后代码跳转到 next_addr继续执行
#define __FLOWER_DEMONS3(rdword, norun)
// 有效的赋值宏，对应的是 address = data
// rand 是随机数据
// run 是任意一段可以执行的花指令
#define __FLOWER_DEMONS4(address, data, rand, run)
#else
#define __FLOWER_DEMONS1 _asm \
{\
	_asm nop\
}
#define __FLOWER_DEMONS2 _asm \
{\
	_asm nop\
	_asm nop\
	_asm nop\
	_asm int 3\
}
#define __FLOWER_DEMONS3(rdword, norun)\
{ \
	_asm push ebx \
	_asm push eax \
	_asm mov ebx, esp \
	_asm sub esp, rdword \
	_asm mov eax, next_addr \
	_asm add esp, rdword \
	_asm push eax \
	_asm retn \
} \
norun \
next_addr: \
{ \
	_asm pop ebx \
	_asm pop eax \
}
#define __FLOWER_DEMONS4(address, data, rand, run)\
{\
	unsigned int nData = (unsigned int)data ^ rand;\
	{\
		_asm push eax\
		_asm push nData\
		_asm mov eax, [esp]\
		_asm add esp, 0x04\
	}\
	run;\
	{\
		_asm xor eax, rand\
		_asm mov address, eax\
		_asm pop eax\
	}\
}
#endif