#pragma once
#define _DEMONS_USED_FLOWER  //�˿��ؿ��Ʊ������Ƿ�ʹ�û�ָ��
#ifndef _DEMONS_USED_FLOWER
#define __FLOWER_DEMONS1	_asm nop
#define __FLOWER_DEMONS2	_asm nop
// rdword��������дһ��16�ֽ����֣�����Ҫ̫��
// norun��һ��ָ���Զ���ᱻִ�У�֮�������ת�� next_addr����ִ��
#define __FLOWER_DEMONS3(rdword, norun)
// ��Ч�ĸ�ֵ�꣬��Ӧ���� address = data
// rand ���������
// run ������һ�ο���ִ�еĻ�ָ��
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