/*******************************************************************************
 * Copyright (c) 2018 Xilinx, Inc. and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 * You may elect to redistribute this code under either of these licenses.
 *
 * Contributors:
 *     Xilinx - initial API and implementation
 *******************************************************************************/

#ifndef D_cpu_regs_gdb_microblazex
#define D_cpu_regs_gdb_microblazex

#include <tcf/config.h>

static const char * cpu_regs_gdb_microblazex =
"<architecture>microblazex</architecture>\n"
"<feature name='org.gnu.gdb.microblazex.core'>\n"
"  <reg name='r0' bitsize='64' id='0' regnum='0'/>\n"
"  <reg name='r1' bitsize='64' id='1' type='data_ptr'/>\n"
"  <reg name='r2' bitsize='64' id='2'/>\n"
"  <reg name='r3' bitsize='64' id='3'/>\n"
"  <reg name='r4' bitsize='64' id='4'/>\n"
"  <reg name='r5' bitsize='64' id='5'/>\n"
"  <reg name='r6' bitsize='64' id='6'/>\n"
"  <reg name='r7' bitsize='64' id='7'/>\n"
"  <reg name='r8' bitsize='64' id='8'/>\n"
"  <reg name='r9' bitsize='64' id='9'/>\n"
"  <reg name='r10' bitsize='64' id='10'/>\n"
"  <reg name='r11' bitsize='64' id='11'/>\n"
"  <reg name='r12' bitsize='64' id='12'/>\n"
"  <reg name='r13' bitsize='64' id='13'/>\n"
"  <reg name='r14' bitsize='64' id='14'/>\n"
"  <reg name='r15' bitsize='64' id='15'/>\n"
"  <reg name='r16' bitsize='64' id='16'/>\n"
"  <reg name='r17' bitsize='64' id='17'/>\n"
"  <reg name='r18' bitsize='64' id='18'/>\n"
"  <reg name='r19' bitsize='64' id='19'/>\n"
"  <reg name='r20' bitsize='64' id='20'/>\n"
"  <reg name='r21' bitsize='64' id='21'/>\n"
"  <reg name='r22' bitsize='64' id='22'/>\n"
"  <reg name='r23' bitsize='64' id='23'/>\n"
"  <reg name='r24' bitsize='64' id='24'/>\n"
"  <reg name='r25' bitsize='64' id='25'/>\n"
"  <reg name='r26' bitsize='64' id='26'/>\n"
"  <reg name='r27' bitsize='64' id='27'/>\n"
"  <reg name='r28' bitsize='64' id='28'/>\n"
"  <reg name='r29' bitsize='64' id='29'/>\n"
"  <reg name='r30' bitsize='64' id='30'/>\n"
"  <reg name='r31' bitsize='64' id='31'/>\n"
"  <reg name='rpc' bitsize='64' id='32' type='code_ptr'/>\n"
"  <reg name='rmsr' bitsize='32' id='33'/>\n"
"  <reg name='rear' bitsize='64' id='34'/>\n"
"  <reg name='resr' bitsize='32' id='35'/>\n"
"  <reg name='rfsr' bitsize='32' id='36'/>\n"
"  <reg name='rbtr' bitsize='64' id='37'/>\n"
"  <reg name='rpvr0' bitsize='32' id='38'/>\n"
"  <reg name='rpvr1' bitsize='32' id='39'/>\n"
"  <reg name='rpvr2' bitsize='32' id='40'/>\n"
"  <reg name='rpvr3' bitsize='32' id='41'/>\n"
"  <reg name='rpvr4' bitsize='32' id='42'/>\n"
"  <reg name='rpvr5' bitsize='32' id='43'/>\n"
"  <reg name='rpvr6' bitsize='32' id='44'/>\n"
"  <reg name='rpvr7' bitsize='32' id='45'/>\n"
"  <reg name='rpvr8' bitsize='64' id='46'/>\n"
"  <reg name='rpvr9' bitsize='64' id='47'/>\n"
"  <reg name='rpvr10' bitsize='32' id='48'/>\n"
"  <reg name='rpvr11' bitsize='32' id='49'/>\n"
"  <reg name='redr' bitsize='32' id='50'/>\n"
"  <reg name='rpid' bitsize='32' id='51'/>\n"
"  <reg name='rzpr' bitsize='32' id='52'/>\n"
"  <reg name='rtlbx' bitsize='32' id='53'/>\n"
"  <reg name='rtlbsx' bitsize='32' id='54'/>\n"
"  <reg name='rtlblo' bitsize='32' id='55'/>\n"
"  <reg name='rtlbhi' bitsize='32' id='56'/>\n"
"  <reg name='slr' bitsize='64' id='57'/>\n"
"  <reg name='shr' bitsize='64' id='58'/>\n"
"</feature>\n";

#endif /* D_cpu_regs_gdb_microblazex */
