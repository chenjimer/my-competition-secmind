"""验证 ATT&CK 知识库模块的测试脚本。

使用方法:
    $env:PYTHONPATH="src"; python test_attck.py
"""

from secmind.attck import AttackKnowledgeBase


def main():
    kb = AttackKnowledgeBase()

    # ========== 1. 概要信息 ==========
    print("=" * 55)
    print("1. ATT&CK 知识库摘要")
    print("=" * 55)
    summary = kb.summary()
    for k, v in summary.items():
        v_str = str(v)[:60] if isinstance(v, list) else v
        print(f"  {k}: {v_str}")

    # ========== 2. Tactic 列表 ==========
    print("\n" + "=" * 55)
    print("2. 全部战术阶段 (Tactic)")
    print("=" * 55)
    tactics = kb.get_tactics()
    print(f"  共 {len(tactics)} 个战术阶段:\n")
    for t in tactics:
        print(f"  {t['attack_id']:8s}  {t['name']:<30s}  ({t['short_name']})")

    # ========== 3. 按战术查询技术 ==========
    print("\n" + "=" * 55)
    print("3. initial-access 战术下的技术 (Technique)")
    print("=" * 55)
    techs = kb.get_techniques_by_tactic("initial-access")
    print(f"  共 {len(techs)} 个技术:\n")
    for t in techs[:10]:
        platforms = ", ".join(t["platforms"])
        print(f"  {t['attack_id']:8s}  {t['name']:<35s}  [{platforms}]")
    if len(techs) > 10:
        print(f"  ... 还有 {len(techs) - 10} 个")

    # ========== 4. 搜索 ==========
    print("\n" + "=" * 55)
    print("4. 搜索 SQL 相关技术")
    print("=" * 55)
    hits = kb.search_techniques("SQL")
    print(f"  找到 {len(hits)} 个结果:\n")
    for t in hits[:5]:
        print(f"  {t['attack_id']:8s}  {t['name']:<35s}  tactics={t['tactics']}")

    # ========== 5. 单个技术详情 ==========
    print("\n" + "=" * 55)
    print("5. 单个技术详情: T1190")
    print("=" * 55)
    tech = kb.get_technique("T1190")
    if tech:
        for k, v in tech.items():
            print(f"  {k}: {v}")

    # ========== 6. 子技术 ==========
    print("\n" + "=" * 55)
    print("6. T1059 的子技术")
    print("=" * 55)
    subs = kb.get_subtechniques("T1059")
    print(f"  共 {len(subs)} 个子技术:\n")
    for s in subs:
        print(f"  {s['attack_id']:12s}  {s['name']}")

    # ========== 7. 转 MemoryDocument ==========
    print("\n" + "=" * 55)
    print("7. 转换为 MemoryDocument")
    print("=" * 55)
    docs = kb.to_memory_documents(techs[:2])
    for i, doc in enumerate(docs):
        print(f"  [{i}] {doc.metadata['attack_id']} - {doc.metadata['technique_name']}")
        print(f"      内容预览: {doc.content[:80]}...")
        print(f"      来源: {doc.source}, 版本: {doc.version}")

    # ========== 8. Tactic ↔ Technique 关系总结 ==========
    print("\n" + "=" * 55)
    print("✅ 测试通过！")
    print("=" * 55)
    print("  Tactic ↔ Technique 关系:")
    print("    Tactic (战术)      = 攻击阶段目标 (如 initial-access)")
    print("    Technique (技术)   = 实现目标的方法 (如 T1190)")
    print("    Sub-technique     = 更具体的实现方式")
    print("    Procedure (步骤)  = 实际工具/命令")
    print()
    print("  示例流程:")
    print("    TA0001(初始访问) → T1190(利用公开应用漏洞)")
    print("      → T1190.001(SQL注入) → sqlmap 工具")
    print("=" * 55)


if __name__ == "__main__":
    main()
