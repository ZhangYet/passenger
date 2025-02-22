; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr }
%"struct map_t.2" = type { ptr, ptr, ptr, ptr }

@LICENSE = local_unnamed_addr global [4 x i8] c"GPL\00", section "license"
@AT_ = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_res = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !20
@ringbuf = dso_local local_unnamed_addr global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !22
@event_loss_counter = dso_local local_unnamed_addr global %"struct map_t.2" zeroinitializer, section ".maps", !dbg !36

define noundef i64 @BEGIN_1(ptr nocapture readnone %0) local_unnamed_addr section "s_BEGIN_1" !dbg !52 {
entry:
  %"@res_val" = alloca i64, align 8
  %"@res_key" = alloca i64, align 8
  %len = alloca i64, align 8
  %"@_val" = alloca i64, align 8
  %"@_key" = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr nonnull %"@_key")
  store i64 42, ptr %"@_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr nonnull %"@_val")
  store i64 1, ptr %"@_val", align 8
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr nonnull @AT_, ptr nonnull %"@_key", ptr nonnull %"@_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr nonnull %"@_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr nonnull %"@_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr nonnull %len)
  store i64 0, ptr %len, align 8
                          %for_each_map_elem = call i64 inttoptr (i64 164 to ptr)(ptr nonnull @AT_, ptr nonnull @map_len_cb, ptr nonnull %len, i64 0)
  %1 = load i64, ptr %len, align 8
  call void @llvm.lifetime.end.p0(i64 -1, ptr nonnull %len)
  %2 = icmp sgt i64 %1, 1
  br i1 %2, label %if_body, label %if_end

if_body:                                          ; preds = %entry
  call void @llvm.lifetime.start.p0(i64 -1, ptr nonnull %"@res_key")
  store i64 0, ptr %"@res_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr nonnull %"@res_val")
  store i64 1, ptr %"@res_val", align 8
  %update_elem1 = call i64 inttoptr (i64 2 to ptr)(ptr nonnull @AT_res, ptr nonnull %"@res_key", ptr nonnull %"@res_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr nonnull %"@res_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr nonnull %"@res_key")
  br label %if_end

if_end:                                           ; preds = %if_body, %entry
  ret i64 0
}

; Function Attrs: mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #0

; Function Attrs: mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #0
                                                        
; Function Attrs: mustprogress nofree norecurse nosync nounwind willreturn memory(argmem: readwrite)
define internal noundef i64 @map_len_cb(ptr nocapture readnone %0, ptr nocapture readnone %1, ptr nocapture readnone %2, ptr nocapture %3) #1 section ".text" !dbg !59 {
  %5 = load i64, ptr %3, align 8
  %6 = add i64 %5, 1
  store i64 %6, ptr %3, align 8
  ret i64 0
}

attributes #0 = { mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #1 = { mustprogress nofree norecurse nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!49}
!llvm.module.flags = !{!51}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !16, !19}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 1, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !12, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 131072, elements: !14)
!14 = !{!15}
!15 = !DISubrange(count: 4096, lowerBound: 0)
!16 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !17, size: 64, offset: 128)
!17 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!18 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!19 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !17, size: 64, offset: 192)
!20 = !DIGlobalVariableExpression(var: !21, expr: !DIExpression())
!21 = distinct !DIGlobalVariable(name: "AT_res", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !24, isLocal: false, isDefinition: true)
!24 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !25)
!25 = !{!26, !31}
!26 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !27, size: 64)
!27 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !28, size: 64)
!28 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !29)
!29 = !{!30}
!30 = !DISubrange(count: 27, lowerBound: 0)
!31 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !32, size: 64, offset: 64)
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !34)
!34 = !{!35}
!35 = !DISubrange(count: 262144, lowerBound: 0)
!36 = !DIGlobalVariableExpression(var: !37, expr: !DIExpression())
!37 = distinct !DIGlobalVariable(name: "event_loss_counter", linkageName: "global", scope: !2, file: !2, type: !38, isLocal: false, isDefinition: true)
!38 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !39)
!39 = !{!40, !45, !46, !19}
!40 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !41, size: 64)
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !42, size: 64)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 64, elements: !43)
!43 = !{!44}
!44 = !DISubrange(count: 2, lowerBound: 0)
!45 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!46 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !47, size: 64, offset: 128)
!47 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !48, size: 64)
!48 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!49 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !50)
!50 = !{!0, !20, !22, !36}
!51 = !{i32 2, !"Debug Info Version", i32 3}
!52 = distinct !DISubprogram(name: "BEGIN_1", linkageName: "BEGIN_1", scope: !2, file: !2, type: !53, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !49, retainedNodes: !57)
!53 = !DISubroutineType(types: !54)
!54 = !{!18, !55}
!55 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !56, size: 64)
!56 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!57 = !{!58}
!58 = !DILocalVariable(name: "ctx", arg: 1, scope: !52, file: !2, type: !55)
!59 = distinct !DISubprogram(name: "map_len_cb", linkageName: "map_len_cb", scope: !2, file: !2, type: !53, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !49, retainedNodes: !60)
!60 = !{!61}
!61 = !DILocalVariable(name: "ctx", arg: 1, scope: !59, file: !2, type: !55)
