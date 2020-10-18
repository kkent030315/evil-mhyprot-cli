//
// Pseudocode
//

ulonglong IOCTL_FUN_0001d000(
uint param_1,
ulonglong *param_2,
uint param_3,
ulonglong **param_4,
int *param_5
)
{
  int iVar1;
  bool bVar2;
  int *piVar3;
  uint uVar4;
  uint uVar5;
  ulonglong uVar6;
  ulonglong *puVar7;
  uint **ppuVar8;
  ulonglong uVar9;
  int **ppiVar10;
  uint unaff_EDI;
  undefined8 uVar11;
  ulonglong **ppuVar12;
  uint *puVar13;
  undefined8 extraout_XMM0_Qb;
  uint local_res20 [2];
  undefined4 *local_2b8;
  undefined4 in_stack_fffffffffffffd50;
  undefined4 in_stack_fffffffffffffd54;
  ulonglong *puVar14;
  ulonglong *local_2a8;
  undefined4 uStack672;
  undefined4 uStack668;
  uint *puStack664;
  undefined4 uStack656;
  undefined4 uStack652;
  undefined4 uStack648;
  undefined4 uStack644;
  undefined4 uStack640;
  undefined4 uStack636;
  undefined8 uStack632;
  undefined4 uStack616;
  undefined4 uStack612;
  undefined4 uStack608;
  undefined4 uStack604;
  undefined4 uStack600;
  undefined4 uStack596;
  undefined4 uStack592;
  undefined4 uStack588;
  undefined8 uStack584;
  int *apiStack568 [66];
  
  piVar3 = param_5;
  uVar6 = (ulonglong)param_3;
  *param_4 = (ulonglong *)0x0;
  puVar13 = local_res20;
  local_2a8 = (ulonglong *)0x0;
  ppuVar12 = (ulonglong **)&stack0xfffffffffffffd58;
  local_res20[0] = 0;
  iVar1 = 0;
  if (unaff_EDI != 0) {
    while ((unaff_EDI >> iVar1 & 1) == 0) {
      iVar1 = iVar1 + 1;
    }
  }
  local_2b8 = &DAT_0001a0e8;
  *param_5 = 0;
  bVar2 = false;
  uVar9 = FUN_00012134(param_2,param_3,ppuVar12,puVar13,&DAT_0001a0e8);
  if ((((int)uVar9 == 0) || (local_2a8 == (ulonglong *)0x0)) || (local_res20[0] == 0)) {
    bVar2 = true;
    local_res20[0] = param_3;
    local_2a8 = param_2;
  }
  if (bVar2) {
    return uVar9 & 0xffffffffffffff00;
  }
  puVar14 = local_2a8;
  if (param_1 < 0x81104001) {
    if (param_1 == 0x81104000) {
      param_5 = (int *)FUN_00016834(*(uint *)local_2a8);
LAB_0001d33a:
      ppiVar10 = &param_5;
      uVar5 = 8;
      goto LAB_0001d5f0;
    }
    puVar7 = (ulonglong *)0x81054000;
    if (0x81054000 < param_1) {
      if (param_1 == 0x81064000) {
        uVar6 = FUN_00013614(*(uint *)local_2a8,uVar6,ppuVar12,puVar13);
        uVar5 = (uint)uVar6;
LAB_0001d2e9:
        param_5 = (int *)CONCAT44(param_5._4_4_,uVar5);
      }
      else {
        if (param_1 == 0x81074000) {
          param_5 = (int *)((ulonglong)param_5._4_4_ << 0x20);
          DispatchReadUserMemory_FUN_00014214((int *)local_2a8,(undefined4 *)&param_5);
        }
        else {
          if (param_1 != 0x81084000) {
            if (param_1 != 0x81094000) goto LAB_0001d62b;
            uVar6 = FUN_000135b0(*(uint *)local_2a8,uVar6,ppuVar12,puVar13);
            uVar5 = (uint)uVar6;
            goto LAB_0001d2e9;
          }
          param_5 = (int *)CONCAT44(param_5._4_4_,0x133ecf0);
        }
      }
LAB_0001d21c:
      uVar5 = 4;
      ppiVar10 = &param_5;
      goto LAB_0001d5f0;
    }
    if (param_1 == 0x81054000) {
      uVar5 = *(uint *)((longlong)local_2a8 + 4);
      uVar4 = *(uint *)local_2a8;
      puVar7 = (ulonglong *)ExAllocatePool(0,(ulonglong)uVar5 * 0x318 + 4);
      uVar6 = FUN_0001274c(uVar4,(longlong)puVar7 + 4,uVar5);
      uVar4 = (uint)uVar6;
      *(uint *)puVar7 = uVar4;
      if (uVar5 < uVar4) {
        uVar4 = uVar5;
      }
      puStack664 = (uint *)CONCAT44(DAT_0001a0ec,DAT_0001a0e8);
      uStack656 = DAT_0001a0f0;
      uStack652 = DAT_0001a0f4;
      uStack648 = DAT_0001a0f8;
      uStack644 = DAT_0001a0fc;
      uStack640 = DAT_0001a100;
      uStack636 = DAT_0001a104;
      uStack632 = DAT_0001a108;
      FUN_00012270(puVar7,uVar4 * 0x318 + 4,param_4,piVar3,&puStack664);
      puVar14 = local_2a8;
LAB_0001d2ac:
      puVar7 = (ulonglong *)ExFreePoolWithTag(puVar7,0);
      goto LAB_0001d62b;
    }
    if (param_1 == 0x80024000) {
      FUN_000148fc(*(uint *)local_2a8);
      param_5 = (int *)((ulonglong)param_5 & 0xffffffff00000000);
      goto LAB_0001d21c;
    }
    if (param_1 == 0x81004000) {
      uVar11 = 0x20;
      FUN_00017900((undefined4 *)&uStack616,0,0x20);
      puVar7 = (ulonglong *)FUN_00014310((longlong *)local_2a8,&uStack616,uVar11,puVar13);
      puVar14 = local_2a8;
      if ((int)puVar7 != 0) goto LAB_0001d62b;
      goto LAB_0001d5e9;
    }
    if (param_1 == 0x81014000) {
      FUN_0001696c(*(uint *)local_2a8);
      uVar6 = FUN_00016994();
      param_5 = (int *)((ulonglong)param_5 & 0xffffffff00000000 | (ulonglong)((char)uVar6 == '\x01')
                       );
LAB_0001d17f:
      ppuVar8 = (uint **)&uStack616;
      uVar5 = 4;
      ppiVar10 = &param_5;
      uStack616 = DAT_0001a0e8;
      uStack612 = DAT_0001a0ec;
      uStack608 = DAT_0001a0f0;
      uStack604 = DAT_0001a0f4;
      uStack584 = DAT_0001a108;
      uStack600 = DAT_0001a0f8;
      uStack596 = DAT_0001a0fc;
      uStack592 = DAT_0001a100;
      uStack588 = DAT_0001a104;
    }
    else {
      if (param_1 == 0x81034000) {
        thunk_FUN_000136b0(*(uint *)local_2a8);
        param_5 = (int *)((ulonglong)param_5 & 0xffffffff00000000);
        goto LAB_0001d17f;
      }
      if (param_1 != 0x81044000) goto LAB_0001d62b;
      uVar5 = *(uint *)local_2a8;
      FUN_00017900((undefined4 *)apiStack568,0,0x208);
      FUN_00013bfc(uVar5,apiStack568,0x104,puVar13);
      ppuVar8 = (uint **)&uStack616;
      uVar5 = 0x208;
      ppiVar10 = apiStack568;
      uStack616 = DAT_0001a0e8;
      uStack612 = DAT_0001a0ec;
      uStack608 = DAT_0001a0f0;
      uStack604 = DAT_0001a0f4;
      uStack584 = DAT_0001a108;
      uStack600 = DAT_0001a0f8;
      uStack596 = DAT_0001a0fc;
      uStack592 = DAT_0001a100;
      uStack588 = DAT_0001a104;
    }
  }
  else {
    puVar7 = (ulonglong *)0x82044000;
    if (param_1 < 0x82044001) {
      if (param_1 == 0x82044000) {
        FUN_00017900((undefined4 *)&uStack616,0,0x20);
        FUN_00016268();
      }
      else {
        if (param_1 == 0x81114000) {
          param_5 = (int *)FUN_00013d44(*(uint *)local_2a8);
          goto LAB_0001d33a;
        }
        if (param_1 == 0x81124000) {
          FUN_000996ed(&LAB_0001db10,uVar6,(ulonglong)ppuVar12);
          FUN_000b7de0();
          uStack672 = (undefined4)extraout_XMM0_Qb;
          uStack668 = (undefined4)((ulonglong)extraout_XMM0_Qb >> 0x20);
          FUN_000cf4a3();
          puStack664 = (uint *)FUN_000add98(DAT_0001a108);
          FUN_000cf4a3();
          uVar6 = FUN_0004609e();
          return uVar6;
        }
        if (param_1 == 0x82004000) {
          param_5 = (int *)((ulonglong)param_5._4_4_ << 0x20);
          FUN_00016408(local_2a8[2],local_2a8[1],*local_2a8,puVar13,local_2b8,
                       (uint *)CONCAT44(in_stack_fffffffffffffd54,in_stack_fffffffffffffd50),
                       local_2a8);
          goto LAB_0001d21c;
        }
        if (param_1 == 0x82014000) {
          FUN_00017900((undefined4 *)&uStack616,0,0x20);
          FUN_00015fa0();
        }
        else {
          if (param_1 != 0x82024000) goto LAB_0001d62b;
          FUN_00017900((undefined4 *)&uStack616,0,0x20);
          FUN_00015f1c();
        }
      }
    }
    else {
      if (param_1 == 0x82054000) {
        FUN_00017900((undefined4 *)&uStack616,0,0x20);
        FUN_000161bc(local_2a8,(int)register0x00000020 - 0x268);
      }
      else {
        if (param_1 != 0x82064000) {
          if (param_1 == 0x82114000) {
            puVar7 = local_2a8;
            if ((*(uint *)local_2a8 ^ 0xbaebaeec) != DAT_0001a688) goto LAB_0001d62b;
            uVar5 = DAT_0001a6ec ^ DAT_0001a688;
            goto LAB_0001d2e9;
          }
          if (((param_1 != 0x83014000) || (*(uint *)local_2a8 != 0x88)) ||
             (puVar7 = (ulonglong *)
                       ExAllocatePool(0,(ulonglong)*(uint *)((longlong)local_2a8 + 4) * 0x2a8 + 4),
             puVar7 == (ulonglong *)0x0)) goto LAB_0001d62b;
          uVar6 = FUN_00016038((longlong)puVar7 + 4,(int *)local_2a8);
          uVar5 = (uint)uVar6;
          *(uint *)puVar7 = uVar5;
          if (*(uint *)((longlong)local_2a8 + 4) < uVar5) {
            uVar5 = *(uint *)((longlong)local_2a8 + 4);
          }
          puStack664 = (uint *)CONCAT44(DAT_0001a0ec,DAT_0001a0e8);
          uStack656 = DAT_0001a0f0;
          uStack652 = DAT_0001a0f4;
          uStack648 = DAT_0001a0f8;
          uStack644 = DAT_0001a0fc;
          uStack640 = DAT_0001a100;
          uStack636 = DAT_0001a104;
          uStack632 = DAT_0001a108;
          FUN_00012270(puVar7,uVar5 * 0x2a8 + 4,param_4,piVar3,&puStack664);
          goto LAB_0001d2ac;
        }
        FUN_00017900((undefined4 *)&uStack616,0,0x20);
        FUN_0001630c((longlong)local_2a8,(undefined4 *)&uStack616);
      }
    }
LAB_0001d5e9:
    ppiVar10 = (int **)&uStack616;
    uVar5 = 0x20;
LAB_0001d5f0:
    ppuVar8 = &puStack664;
    puStack664 = (uint *)CONCAT44(DAT_0001a0ec,DAT_0001a0e8);
    uStack656 = DAT_0001a0f0;
    uStack652 = DAT_0001a0f4;
    uStack632 = DAT_0001a108;
    uStack648 = DAT_0001a0f8;
    uStack644 = DAT_0001a0fc;
    uStack640 = DAT_0001a100;
    uStack636 = DAT_0001a104;
  }
  puVar7 = (ulonglong *)FUN_00012270(ppiVar10,uVar5,param_4,piVar3,ppuVar8);
  puVar14 = local_2a8;
LAB_0001d62b:
  if (puVar14 != (ulonglong *)0x0) {
    puVar7 = (ulonglong *)ExFreePoolWithTag(puVar14,0);
  }
  return CONCAT71((int7)((ulonglong)puVar7 >> 8),1);
}
