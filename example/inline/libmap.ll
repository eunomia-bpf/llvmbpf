; ModuleID = 'libmap.c'
source_filename = "libmap.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@ctl_array = dso_local global [2 x i32] zeroinitializer, align 4
@cntrs_array = dso_local global [2 x i64] zeroinitializer, align 16

; Function Attrs: mustprogress nofree norecurse nosync nounwind willreturn memory(argmem: read) uwtable
define dso_local ptr @_bpf_helper_ext_0001(i64 noundef %0, ptr nocapture noundef readonly %1) local_unnamed_addr #0 {
  switch i64 %0, label %11 [
    i64 5, label %3
    i64 6, label %7
  ]

3:                                                ; preds = %2
  %4 = load i32, ptr %1, align 4, !tbaa !5
  %5 = zext i32 %4 to i64
  %6 = getelementptr inbounds [2 x i32], ptr @ctl_array, i64 0, i64 %5
  br label %11

7:                                                ; preds = %2
  %8 = load i32, ptr %1, align 4, !tbaa !5
  %9 = zext i32 %8 to i64
  %10 = getelementptr inbounds [2 x i64], ptr @cntrs_array, i64 0, i64 %9
  br label %11

11:                                               ; preds = %2, %7, %3
  %12 = phi ptr [ %6, %3 ], [ %10, %7 ], [ null, %2 ]
  ret ptr %12
}

; Function Attrs: mustprogress nofree norecurse nosync nounwind willreturn memory(none) uwtable
define dso_local noundef ptr @__lddw_helper_map_val(i64 noundef %0) local_unnamed_addr #1 {
  %2 = icmp eq i64 %0, 6
  %3 = select i1 %2, ptr @cntrs_array, ptr null
  %4 = icmp eq i64 %0, 5
  %5 = select i1 %4, ptr @ctl_array, ptr %3
  ret ptr %5
}

attributes #0 = { mustprogress nofree norecurse nosync nounwind willreturn memory(argmem: read) uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { mustprogress nofree norecurse nosync nounwind willreturn memory(none) uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.module.flags = !{!0, !1, !2, !3}
!llvm.ident = !{!4}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{!"Ubuntu clang version 18.1.3 (1ubuntu1)"}
!5 = !{!6, !6, i64 0}
!6 = !{!"int", !7, i64 0}
!7 = !{!"omnipotent char", !8, i64 0}
!8 = !{!"Simple C/C++ TBAA"}
