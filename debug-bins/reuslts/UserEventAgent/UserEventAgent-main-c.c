
void main(int32_t param_1, int64_t param_2)

{
    uint uVar1;
    int32_t iVar2;
    int32_t iVar3;
    ulong uVar4;
    int64_t iVar5;
    uint *puVar6;
    code *UNRECOVERED_JUMPTABLE;
    ulong uStack_e8;
    int64_t iStack_e0;
    int64_t iStack_d8;
    uint uStack_d0;
    uint uStack_cc;
    ushort uStack_c8;
    ulong uStack_c6;
    uint64_t uStack_b0;
    ulong uStack_a8;
    ulong uStack_a0;
    ulong uStack_98;
    ulong uStack_90;
    ulong uStack_88;
    ulong uStack_80;
    ulong uStack_78;
    ulong uStack_70;
    ulong uStack_68;
    ulong uStack_58;
    
    uStack_58 = **reloc.__stack_chk_guard;
    uVar4 = sym.imp.os_log_create(sym.imp.free + 0x4e8, sym.imp.free + 0x501);
    *0x10000c040 = uVar4;
    iStack_e0 = 0;
    iStack_d8 = 0;
    iVar2 = sym.imp.setiopolicy_np(9, 0, 1);
    if (iVar2 != 0) {
        uStack_e8 = 0;
        uStack_78 = 0;
        uStack_80 = 0;
        uStack_68 = 0;
        uStack_70 = 0;
        uStack_98 = 0;
        uStack_a0 = 0;
        uStack_88 = 0;
        uStack_90 = 0;
        uStack_a8 = 0;
        uStack_b0 = 0;
        uVar4 = *reloc._os_log_default;
        iVar3 = sym.imp.os_log_type_enabled(uVar4, 0x10);
        iVar2 = 2;
        if (iVar3 != 0) {
            iVar2 = iVar2 + 1;
        }
        puVar6 = sym.imp.__error();
        uVar1 = *puVar6;
        puVar6 = sym.imp.__error();
        uStack_c6 = sym.imp.strerror(*puVar6);
        uStack_d0 = *0x100007480;
        uStack_c8 = 0x822;
        uStack_cc = uVar1;
        uVar4 = sym.imp._os_log_send_and_compose_impl
                          (iVar2, &uStack_e8, &uStack_b0, 0x50, 0 + 0x100000000, uVar4, 0x10, sym.imp.free + 0x71b);
        sym.imp._os_crash_msg(uStack_e8, uVar4);
    // WARNING: Treating indirect jump as call
        UNRECOVERED_JUMPTABLE = SoftwareBreakpoint(1, 0x100004bc0);
        (*UNRECOVERED_JUMPTABLE)();
        return;
    }
    if (*0x10000c070 != -1) {
        sym.imp.dispatch_once(segment.__DATA + 0x70, segment.__DATA_CONST + 0x3d0);
    }
    iVar5 = sym.imp.objc_alloc_init(*reloc.NSMutableSet);
    *0x10000c048 = iVar5;
    if (iVar5 == 0) {
        uVar4 = *0x10000c040;
        iVar2 = sym.imp.os_log_type_enabled(uVar4, 0x10);
        if (iVar2 == 0) goto code_r0x000100004ad8;
        uStack_b0 = (uStack_b0 >> 0x10) << 0x10;
        iVar5 = 0 + 0x100000000;
        UNRECOVERED_JUMPTABLE = sym.imp.free + 0x74e;
    }
    else {
        iVar5 = sym.imp.objc_alloc_init(*reloc.NSMutableSet);
        *0x10000c050 = iVar5;
        if (iVar5 == 0) {
            uVar4 = *0x10000c040;
            iVar2 = sym.imp.os_log_type_enabled(uVar4, 0x10);
            if (iVar2 == 0) goto code_r0x000100004ad8;
            uStack_b0 = (uStack_b0 >> 0x10) << 0x10;
            iVar5 = 0 + 0x100000000;
            UNRECOVERED_JUMPTABLE = sym.imp.free + 0x74e;
        }
        else {
            sym.imp.CFBundleGetMainBundle();
            if (*0x10000c078 != -1) {
                sym.imp.dispatch_once(segment.__DATA + 0x78, segment.__DATA_CONST + 0x3f0);
            }
            if ((param_1 + -4 < 0 == SBORROW4(param_1, 4)) && (*0x10000c080 != '\0')) {
                uVar4 = *(param_2 + 0x10);
                iVar2 = sym.imp.strncmp(uVar4, sym.imp.free + 0x508, 2);
                if (iVar2 == 0) {
                    param_1 = param_1 + -3;
                    *0x10000c058 = param_1;
                    *0x10000c05c = 1;
                    uVar4 = *0x10000c040;
                    iVar2 = sym.imp.os_log_type_enabled(uVar4, 2);
                    if (iVar2 == 0) goto code_r0x000100004990;
                    iVar5 = 0 + 0x100000000;
                    UNRECOVERED_JUMPTABLE = sym.imp.free + 0x766;
code_r0x000100004960:
                    uStack_b0 = (uStack_b0 >> 0x10) << 0x10;
                    sym.imp._os_log_debug_impl(iVar5, uVar4, 2, UNRECOVERED_JUMPTABLE, &uStack_b0, 2);
code_r0x000100004974:
                    param_1 = *0x10000c058;
                    *0x10000c060 = param_2 + 0x18;
                    if (param_1 + -1 < 0 == SBORROW4(param_1, 1)) goto code_r0x000100004998;
                }
                else {
                    iVar2 = sym.imp.strncmp(uVar4, sym.imp.free + 0x50a, 2);
                    if (iVar2 != 0) goto code_r0x000100004974;
                    param_1 = param_1 + -3;
                    *0x10000c058 = param_1;
                    *0x10000c05d = 1;
                    uVar4 = *0x10000c040;
                    iVar2 = sym.imp.os_log_type_enabled(uVar4, 2);
                    if (iVar2 != 0) {
                        iVar5 = 0 + 0x100000000;
                        UNRECOVERED_JUMPTABLE = sym.imp.free + 0x790;
                        goto code_r0x000100004960;
                    }
code_r0x000100004990:
                    *0x10000c060 = param_2 + 0x18;
code_r0x000100004998:
                    if ((*0x10000c05c != '\x01') || (param_1 == 1)) goto code_r0x0001000049bc;
                }
                *0x10000c05c = 0;
                *0x10000c05d = 0;
                *0x10000c060 = 0;
            }
code_r0x0001000049bc:
            sym.imp.vproc_swap_integer(0, 5, 0, &iStack_d8);
            if (iStack_d8 == 0) {
                sym.imp.fwrite(sym.imp.free + 0x50c, 0x2e, 1, **reloc.__stderrp);
                goto code_r0x000100004ad8;
            }
            sym.imp.vproc_swap_string(0, 6, 0, &iStack_e0);
            if (iStack_e0 == 0) {
                uVar4 = *0x10000c040;
                iVar2 = sym.imp.os_log_type_enabled(uVar4, 0x10);
                if (iVar2 == 0) goto code_r0x000100004ad8;
                uStack_b0 = (uStack_b0 >> 0x10) << 0x10;
                iVar5 = 0 + 0x100000000;
                UNRECOVERED_JUMPTABLE = sym.imp.free + 0x7c3;
            }
            else {
                sym.imp.signal(0xf, 1);
                iVar5 = sym.imp.dispatch_get_global_queue(0x15, 0);
                if (iVar5 == 0) {
                    uVar4 = *0x10000c040;
                    iVar2 = sym.imp.os_log_type_enabled(uVar4, 0x10);
                    if (iVar2 != 0) {
                        iVar5 = 0 + 0x100000000;
                        UNRECOVERED_JUMPTABLE = sym.imp.free + 0x8aa;
code_r0x000100004a88:
                        uStack_b0 = (uStack_b0 >> 0x10) << 0x10;
                        sym.imp._os_log_error_impl(iVar5, uVar4, 0x10, UNRECOVERED_JUMPTABLE, &uStack_b0, 2);
                    }
                }
                else {
                    iVar5 = sym.imp.dispatch_source_create(*reloc._dispatch_source_type_signal, 0xf, 0, iVar5);
                    *0x10000c088 = iVar5;
                    if (iVar5 != 0) {
                        sym.imp.dispatch_source_set_event_handler(iVar5, segment.__DATA_CONST + 0x410);
                        sym.imp.dispatch_activate(*0x10000c088);
                        if (*reloc.CTTelephonyCenterGetDefault != 0) {
                            sym.imp.CTTelephonyCenterGetDefault();
                        }
                        sym.func.100005e90(0);
                        *0x10000c068 = 0;
                        sym.func.100004d88(iStack_e0, 1, sym.imp.free + 0x53b);
                        sym.func.100004d88(iStack_e0, 1, sym.imp.free + 0x569);
                        if (*reloc.CGSMainConnectionID != 0) {
                            sym.imp.CGSMainConnectionID();
                        }
                        sym.func.100004d88(iStack_e0, 0, sym.imp.free + 0x53b);
                        sym.func.100004d88(iStack_e0, 0, sym.imp.free + 0x569);
                        iVar5 = iStack_e0;
                        iVar2 = sym.imp.strcmp(iVar5, sym.imp.free + 0x589);
                        if (iVar2 != 0) {
                            sym.func.100005e90(1);
                            iVar5 = iStack_e0;
                        }
                        sym.imp.free(iVar5);
                        sym.imp.objc_release(*0x10000c048);
                        sym.imp.objc_release(*0x10000c050);
                        uVar4 = *0x10000c040;
                        iVar2 = sym.imp.os_log_type_enabled(uVar4, 0);
                        if (iVar2 != 0) {
                            uStack_b0 = (uStack_b0 >> 0x10) << 0x10;
                            sym.imp._os_log_impl(0 + 0x100000000, uVar4, 0, sym.imp.free + 0x804, &uStack_b0, 2);
                        }
                        fcn.1000073c0(*reloc.NSRunLoop);
                        fcn.100007420();
                        goto code_r0x000100004ad8;
                    }
                    uVar4 = *0x10000c040;
                    iVar2 = sym.imp.os_log_type_enabled(uVar4, 0x10);
                    if (iVar2 != 0) {
                        iVar5 = 0 + 0x100000000;
                        UNRECOVERED_JUMPTABLE = sym.imp.free + 0x8be;
                        goto code_r0x000100004a88;
                    }
                }
                uVar4 = *0x10000c040;
                iVar2 = sym.imp.os_log_type_enabled(uVar4, 0x10);
                if (iVar2 == 0) goto code_r0x000100004ad8;
                uStack_b0 = (uStack_b0 >> 0x10) << 0x10;
                iVar5 = 0 + 0x100000000;
                UNRECOVERED_JUMPTABLE = sym.imp.free + 0x7df;
            }
        }
    }
    sym.imp._os_log_error_impl(iVar5, uVar4, 0x10, UNRECOVERED_JUMPTABLE, &uStack_b0, 2);
code_r0x000100004ad8:
    // WARNING: Subroutine does not return
    sym.imp.exit(1);
}
