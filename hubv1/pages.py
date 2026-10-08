from __future__ import annotations

import html
import json
from typing import Optional
from urllib.parse import quote

from fastapi.responses import HTMLResponse, RedirectResponse, Response

from hubv1.acl import access_for
from hubv1.align import slot_view, unread_slots
from hubv1.store import connect
from hubv1 import timeutil


def nav(p, current: str) -> str:
    items = [
        ("/console", "概览"),
        ("/console/library", "资料库"),
        ("/console/logs", "今日日志"),
        ("/console/chat", "聊天区"),
        ("/console/workspaces/me", "我的工作区"),
        ("/console/workspaces", "全部工作区"),
        ("/console/workspace", "文章"),
        ("/console/publish", "发布"),
        ("/console/profile", "两份资料"),
        ("/console/access", "接入与权限"),
        ("/console/connections", "OAuth 连接"),
    ]
    links = []
    for href, label in items:
        cls = "on" if current == href else ""
        links.append(f'<a class="{cls}" href="{href}">{html.escape(label)}</a>')
    return (
        f'<nav class="nav">{"".join(links)}'
        f'<span class="muted" style="margin-left:auto">{html.escape(p.id)}</span>'
        f'<form method="post" action="/session/logout" style="margin:0"><button type="submit">退出</button></form></nav>'
    )


def extra_css() -> str:
    return """
    .nav { display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin:0 0 18px; padding:10px 0; border-bottom:1px solid #2a3644; }
    .nav a { color:#9ecbff; text-decoration:none; padding:6px 10px; border-radius:999px; border:1px solid transparent; }
    .nav a.on { background:#1f6feb33; border-color:#388bfd66; }
    .empty { color:#9aa7b8; padding:12px 0; }
    .warn { color:#ffb347; }
    pre.diff { white-space:pre-wrap; background:#10161d; padding:12px; border-radius:10px; overflow:auto; }
    textarea { width:100%; min-height:120px; background:#0f1419; color:#e7ecf3; border:1px solid #2a3644; border-radius:10px; padding:10px; }
    """


def wrap(page_shell, title: str, p, current: str, inner: str) -> Response:
    body = nav(p, current) + inner
    html_doc = page_shell(title, body).replace("</style>", extra_css() + "</style>")
    return HTMLResponse(html_doc)


def overview_page(page_shell, p) -> Response:
    acc = access_for(p)
    day = timeutil.shanghai_date()
    unread = unread_slots(p.id)
    with connect() as conn:
        projects = conn.execute("SELECT project_id, title, version, status FROM projects").fetchall()
        pending = conn.execute("SELECT COUNT(*) AS n FROM proposals WHERE status='open'").fetchone()["n"]
        seen = conn.execute("SELECT last_seen_at FROM last_seen WHERE identity_id=?", (p.id,)).fetchone()
    vis_proj = [r for r in projects if acc.can_read_project(r["project_id"])]
    write_proj = [r for r in vis_proj if acc.manage or acc.in_project(r["project_id"])]
    slots = []
    for hour in (8, 20):
        view = slot_view(p.id, day, hour, p)
        status_map = {
            "scheduled": "未到截止",
            "published": "已发布",
            "empty": "空简报",
            "catchup": "补跑",
            "failed": "失败",
        }
        note_map = {
            "scheduled": "到期后才会生成；未生成不算未读",
            "published": view.get("generated_at") or view.get("slot_id") or "",
            "empty": view.get("empty_reason") or "暂无工作摘要",
            "catchup": "补跑产物，不是当时准时生成",
            "failed": "生成失败，实时区消息仍保留",
        }
        slots.append(
            {
                "label": f"{hour:02d}:00",
                "status": status_map.get(view["status"], view["status"]),
                "note": note_map.get(view["status"], ""),
                "ready": view["status"] != "scheduled",
                "generated": view["status"] in {"published", "empty", "catchup"},
            }
        )
    if not vis_proj:
        read_html = "<p class='empty'>还没有共享项目。所有者创建项目后，持 token 的 Agent 即可阅读。此处不展示示例数据。</p>"
    else:
        lis = "".join(
            f"<li>{html.escape(r['title'])} <span class='muted'>v{r['version']} {html.escape(r['status'])}</span></li>"
            for r in vis_proj
        )
        read_html = f"<ul>{lis}</ul>"
    if not write_proj:
        write_html = "<p class='empty'>尚未授予本身份的项目写权限。可读不等于可写。</p>"
    else:
        wlis = "".join(
            f"<li>{html.escape(r['title'])} <span class='muted'>{html.escape(r['project_id'])}</span></li>"
            for r in write_proj
        )
        write_html = f"<ul>{wlis}</ul>"
    slot_html = "".join(
        f"<div class='card'><div class='muted'>{html.escape(s['label'])}</div>"
        f"<div>{html.escape(s['status'])}</div>"
        f"<div class='muted'>{html.escape(s['note'])}</div></div>"
        for s in slots
    )
    unread_note = "；".join(unread) if unread else "没有已生成且未读的摘要"
    pending_txt = str(pending) if acc.manage else "—"
    seen_txt = seen["last_seen_at"] if seen else "未知"
    inner = f"""
    <p class="pill">v1.1.1 · 私有控制台</p>
    <h1>概览</h1>
    <p class="muted">业务日 {html.escape(day)} Asia/Shanghai · 心跳 {html.escape(seen_txt)}</p>
    <div class="grid">{slot_html}
      <div class="card"><div class="muted">待所有者决定</div><div class="num">{html.escape(pending_txt)}</div></div>
      <div class="card"><div class="muted">已生成未读</div><div class="num">{len(unread)}</div>
        <div class="muted">{html.escape(unread_note)}</div></div>
    </div>
    <section class="card" style="margin-top:16px"><h2 style="margin:0 0 8px;font-size:1.1rem">共享项目</h2>
      <p class="muted">持有效 token 即可阅读共享项目，不必先加入成员列表。</p>{read_html}</section>
    <section class="card" style="margin-top:16px"><h2 style="margin:0 0 8px;font-size:1.1rem">可写项目</h2>
      <p class="muted">创建、修改、删除、上传仍按项目写授权；服务端校验。</p>{write_html}</section>
    """
    return wrap(page_shell, "概览", p, "/console", inner)


def library_page(page_shell, p, q: str = "", kind: str = "") -> Response:
    acc = access_for(p)
    with connect() as conn:
        rows = conn.execute("SELECT * FROM library_items ORDER BY created_at DESC LIMIT 80").fetchall()
    cards = []
    for r in rows:
        if kind and r["type"] != kind:
            continue
        if q and q.lower() not in (r["title"] + r["summary"]).lower():
            continue
        if not acc.can_read_record(r["acl"], r["project_id"]):
            continue
        stale = " · 已过期" if r["stale"] else ""
        sup = " · 已被替代" if r["superseded_by"] else ""
        fs = r["file_status"] if "file_status" in r.keys() else ""
        src = (r["source_url"] if "source_url" in r.keys() else "") or r["source_ref"] or ""
        if not fs:
            fs = "link_only" if str(src).lower().startswith("http") else "missing"
        labels = {"uploaded": "已上传", "link_only": "仅外链", "missing": "文件缺失", "pending_ocr": "待文本提取"}
        ts = r["text_status"] if "text_status" in r.keys() else ""
        if ts in {"pending_ocr", "pending"}:
            fs_label = "待文本提取"
        else:
            fs_label = labels.get(fs, fs or "仅外链")
        cards.append(
            f"<div class='card'><div class='muted'>{html.escape(r['type'])} {html.escape(r['review_status'])} · {html.escape(fs_label)}{stale}{sup}</div>"
            f"<strong>{html.escape(r['title'])}</strong>"
            f"<p>{html.escape(r['summary'])}</p>"
            f"<p class='muted'>{html.escape(r['item_id'])}@v{r['version']} · {html.escape(src or '无链接')} · {html.escape(r['captured_at'])}</p></div>"
        )
    if not cards:
        if q or kind:
            empty = "<p class='empty'>无结果（已按权限过滤）。与无权访问不同：无权条目不会出现在搜索命中中。</p>"
        else:
            empty = "<p class='empty'>资料库还没有你能看的条目。</p>"
        cards_html = empty
    else:
        cards_html = "<div class='grid'>" + "".join(cards) + "</div>"
    form = f"""
    <form method="get" action="/console/library">
      <input name="q" value="{html.escape(q)}" placeholder="标题或摘要关键词">
      <input name="type" value="{html.escape(kind)}" placeholder="类型">
      <button type="submit">筛选</button>
    </form>
    """
    inner = f"<h1>资料库</h1><p class='muted'>原文与摘要分离。引用使用 item_id 与版本。</p>{form}{cards_html}"
    return wrap(page_shell, "资料库", p, "/console/library", inner)


def logs_page(page_shell, p) -> Response:
    acc = access_for(p)
    day = timeutil.shanghai_date()
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM worklog_entries WHERE work_date=? ORDER BY received_at",
            (day,),
        ).fetchall()
    others, mine = [], []
    for r in rows:
        sm = json.loads(r["summary"])
        block = (
            f"<div class='card'><div class='muted'>{html.escape(r['author_agent_id'])} · {html.escape(r['project_id'])} · {html.escape(r['received_at'])}</div>"
            f"<div>完成：{html.escape(sm.get('done') or '—')}</div>"
            f"<div>结果：{html.escape(sm.get('result') or '—')} <span class='muted'>{html.escape(r['verification_status'])}</span></div>"
            f"<div>阻塞：{html.escape(sm.get('blocker') or '无')}</div>"
            f"<div>下一步：{html.escape(sm.get('next') or '—')}</div>"
            f"<div class='muted'>证据 {' '.join(html.escape(x) for x in json.loads(r['evidence_refs'] or '[]')) or '无'}</div></div>"
        )
        if r["author_agent_id"] == p.id:
            mine.append(block)
        elif acc.can_read_project(r["project_id"]):
            others.append(block)
    late_note = ""
    if timeutil.now() >= timeutil.slot_cutoff(day, 20):
        late_note = "<p class='muted'>20:00 之后的写入仍属今天，但不会改写已生成的 20:00 快照。</p>"
    inner = f"""
    <h1>今日日志</h1>
    <p class="muted">{html.escape(day)} Asia/Shanghai</p>
    {late_note}
    <section class="card"><h2 style="margin:0 0 8px;font-size:1.1rem">其他 Agent</h2>
    {''.join(others) or "<p class='empty'>暂无工作摘要</p>"}</section>
    <section class="card" style="margin-top:16px"><h2 style="margin:0 0 8px;font-size:1.1rem">我的日志</h2>
    {''.join(mine) or "<p class='empty'>你今天还没有写入。</p>"}</section>
    """
    if acc.has_scope("worklog:write") or acc.p.has("report") or acc.manage:
        inner += """
        <section class="card" style="margin-top:16px">
          <h2 style="margin:0 0 8px;font-size:1.1rem">追加短摘要</h2>
          <form method="post" action="/console/worklogs">
            <input name="project_id" required placeholder="project_id">
            <input name="done" maxlength="300" placeholder="完成（最多 3 项，分号分隔）">
            <input name="result" maxlength="300" placeholder="结果">
            <input name="blocker" maxlength="300" placeholder="阻塞（最多 2 项）">
            <input name="next" maxlength="300" placeholder="下一步（最多 2 项）">
            <button type="submit">写入今天</button>
          </form>
        </section>
        """
    else:
        inner += "<p class='muted'>当前身份没有 worklog:write。可以阅读共享日志，不能提交或改他人日志。新增写权限需所有者批准。</p>"
    return wrap(page_shell, "今日日志", p, "/console/logs", inner)


def chat_page(page_shell, p, thread_id: str = "", on: str = "") -> Response:
    acc = access_for(p)
    from hubv1.chat import live_dates

    live = live_dates()
    with connect() as conn:
        threads = conn.execute("SELECT * FROM chat_threads ORDER BY created_at DESC").fetchall()
        msgs = []
        th = None
        dates = []
        if thread_id:
            th = conn.execute("SELECT * FROM chat_threads WHERE thread_id=?", (thread_id,)).fetchone()
            if th and (not th["project_id"] or acc.can_chat(th["project_id"])):
                dates = [
                    r["local_date"]
                    for r in conn.execute(
                        "SELECT DISTINCT local_date FROM chat_messages WHERE thread_id=? AND local_date IS NOT NULL AND local_date<>'' ORDER BY local_date DESC LIMIT 30",
                        (thread_id,),
                    ).fetchall()
                ]
                if on:
                    msgs = conn.execute(
                        "SELECT * FROM chat_messages WHERE thread_id=? AND local_date=? ORDER BY COALESCE(event_seq,0), created_at",
                        (thread_id, on),
                    ).fetchall()
                else:
                    msgs = conn.execute(
                        """
                        SELECT * FROM chat_messages
                        WHERE thread_id=? AND (archive_id IS NULL OR archive_id='')
                        ORDER BY COALESCE(event_seq,0), created_at
                        """,
                        (thread_id,),
                    ).fetchall()
    tlist = []
    for t in threads:
        if t["project_id"] and not acc.can_chat(t["project_id"]):
            continue
        if t["project_id"] is None and not acc.manage:
            continue
        tlist.append(f"<li><a href='/console/chat?thread={quote(t['thread_id'])}'>{html.escape(t['title'])}</a> <span class='muted'>{html.escape(t['project_id'] or '跨项目')}</span></li>")
    hist = ""
    if thread_id and dates:
        links = []
        for d in dates:
            label = d
            if d == live[1]:
                label = f"{d} 今日"
            elif d == live[0]:
                label = f"{d} 昨日"
            cls = "on" if on == d else ""
            links.append(f"<a class='{cls}' href='/console/chat?thread={quote(thread_id)}&on={quote(d)}'>{html.escape(label)}</a>")
        hist = "<p class='muted'>历史：" + " · ".join(links) + "</p>"
    if thread_id and not th:
        msg_html = "<p class='empty'>线程不存在或无权查看标题与摘要。</p>"
    elif not msgs and thread_id:
        msg_html = "<p class='empty'>这条线程在当前范围还没有消息。归档失败时旧日会暂时留在实时区。</p>"
    else:
        msg_html = "".join(
            f"<div class='card' id='{html.escape(m['message_id'])}'><div class='muted'>{html.escape(m['author'])} · {html.escape(m['created_at'])}"
            f"{' · 待所有者' if m['pending_owner'] else ''}"
            f"{' · 回复 ' + html.escape(m['reply_to']) if m['reply_to'] else ''}</div><p>{html.escape(m['body'])}</p></div>"
            for m in msgs
        )
    compose = ""
    if thread_id and th and acc.can_chat(th["project_id"], write=True) and (not on or on in live):
        compose = f"""
        <form method="post" action="/console/chat/{html.escape(thread_id)}">
          <textarea name="body" required maxlength="4000" placeholder="提问或澄清。提及某人只是待办，不会唤醒对方。"></textarea>
          <input name="reply_to" maxlength="80" placeholder="可选：回复的 message_id">
          <label><input type="checkbox" name="pending_owner" value="1"> 等待所有者决定</label>
          <button type="submit">发送</button>
        </form>
        """
    inner = f"""
    <h1>聊天区</h1>
    <p class="muted">实时区为 Asia/Shanghai 今日与昨日。更早日期先归档 Markdown 再移出实时列表；原消息 ID 可继续引用。Agent 看到新消息不会自动回复。</p>
    {hist}
    <div class="grid">
      <div class="card"><h2 style="margin:0 0 8px;font-size:1.1rem">线程</h2>
        {"<ul>"+''.join(tlist)+"</ul>" if tlist else "<p class='empty'>没有线程。</p>"}
      </div>
      <div class="card" style="grid-column: span 2"><h2 style="margin:0 0 8px;font-size:1.1rem">消息</h2>{msg_html or "<p class='empty'>选择一个线程。</p>"}{compose}</div>
    </div>
    """
    return wrap(page_shell, "聊天区", p, "/console/chat", inner)


def agent_workspaces_page(page_shell, p, *, mine_only: bool = False, err: str = "") -> Response:
    from hubv1 import workspace as wsmod

    acc = access_for(p)
    mine = wsmod.workspace_of(p.id) if acc.is_authed_reader() else None
    items = []
    for w in wsmod.list_workspaces():
        if not wsmod.can_read_workspace(acc, w):
            continue
        if mine_only and mine and w["workspace_id"] != mine["workspace_id"]:
            continue
        writable = wsmod.can_write_workspace(acc, w)
        nodes = wsmod.list_files(w["workspace_id"])
        files = "".join(
            f"<li><a href='/api/v1/nodes/{html.escape(n['node_id'])}/file'>{html.escape(n.get('path') or n['name'] or '/')}</a>"
            f" · {html.escape(str(n.get('mime_type') or n['kind']))} · {int(n.get('size_bytes') or 0)} 字节"
            f"{' （回收站）' if n.get('deleted_at') else ''}</li>"
            for n in nodes
        ) or "<li class='empty'>空目录</li>"
        form = ""
        if writable:
            form = f"""
            <form method="post" action="/console/workspaces/{html.escape(w['workspace_id'])}/uploads" enctype="multipart/form-data">
              <p>上传附件。ZIP / TAR 会解压到以压缩包命名的目录；单文件不超过 200MB。</p>
              <input type="file" name="file" required accept=".zip,.tar,.gz,.tgz,.7z,.md,.txt,.json,.csv,.pdf,application/zip,application/x-tar,application/gzip">
              <button type="submit">上传附件</button>
            </form>
            <form method="post" action="/console/workspaces/{html.escape(w['workspace_id'])}/nodes">
              <input name="name" required maxlength="160" placeholder="文件名">
              <textarea name="body" maxlength="20000" placeholder="正文"></textarea>
              <button type="submit">新建文本文件</button>
            </form>
            """
        items.append(
            f"<section class='card' style='margin-top:12px'><h2 style='margin:0 0 8px;font-size:1.1rem'>"
            f"{html.escape(w['display_slug'])} · {html.escape(w['owner_agent_id'])}</h2>"
            f"<p class='muted'>更新 {html.escape(w['updated_at'] or '')} · "
            f"{'可写' if writable else '只读'} · 用量 {w['used_bytes']}/{w['quota_bytes']}</p>"
            f"<ul>{files}</ul>{form}</section>"
        )
    title = "我的工作区" if mine_only else "全部 Agent 工作区"
    note = "只有主人和管理员能改这个目录。其他已认证 Agent 可以读和下载。ZIP/TAR 会解压进工作区；单文件 200MB，每人配额 50GB。发布 GitHub 须另走审批。"
    err_html = f"<p class='warn'>{html.escape(err)}</p>" if err else ""
    inner = f"<h1>{title}</h1><p class='muted'>{note}</p>{err_html}{''.join(items) or '<p class=empty>还没有工作区。</p>'}"
    current = "/console/workspaces/me" if mine_only else "/console/workspaces"
    return wrap(page_shell, title, p, current, inner)


def workspace_page(page_shell, p, article_id: str = "") -> Response:
    acc = access_for(p)
    with connect() as conn:
        arts = conn.execute("SELECT * FROM articles ORDER BY updated_at DESC").fetchall()
        art = None
        vers = []
        body = ""
        if article_id:
            art = conn.execute("SELECT * FROM articles WHERE article_id=?", (article_id,)).fetchone()
            if art and acc.can_read_project(art["project_id"]):
                from hubv1.store import read_canonical

                vers = conn.execute(
                    "SELECT version, review_state, created_by, created_at, content_hash FROM article_versions WHERE article_id=? ORDER BY version",
                    (article_id,),
                ).fetchall()
                if art["current_version"]:
                    body = read_canonical("articles", article_id, art["current_version"])
            else:
                art = None
    lis = []
    for a in arts:
        if not acc.can_read_project(a["project_id"]):
            continue
        lis.append(
            f"<li><a href='/console/workspace?article={quote(a['article_id'])}'>{html.escape(a['title'])}</a> "
            f"<span class='muted'>v{a['current_version']} {html.escape(a['review_state'])}</span></li>"
        )
    detail = "<p class='empty'>选择一篇文章。未获批准不能发布。</p>"
    if art:
        hist = "".join(
            f"<li>v{v['version']} {html.escape(v['review_state'])} {html.escape(v['created_by'])} {html.escape(v['created_at'])}</li>"
            for v in vers
        )
        pub = ""
        if acc.manage and art["review_state"] == "approved":
            pub = f"""<form method="post" action="/console/publish"><input type="hidden" name="article_id" value="{html.escape(art['article_id'])}">
            <input type="hidden" name="version" value="{art['current_version']}"><button type="submit">发布已批准版本到本控制台</button></form>"""
        elif art["review_state"] != "published":
            pub = "<p class='muted'>未获批准不能发布。批准后若内容再变，必须重新审阅。</p>"
        if art["publish_url"]:
            pub += f"<p>已发布：<a href='{html.escape(art['publish_url'])}'>{html.escape(art['publish_url'])}</a></p>"
        detail = f"""
        <h2 style="margin-top:0">{html.escape(art['title'])}</h2>
        <p class="muted">{html.escape(art['article_id'])} · {html.escape(art['review_state'])} · v{art['current_version']}</p>
        <pre class="diff">{html.escape(body or '（尚无正文）')}</pre>
        <h3>版本</h3><ul>{hist or '<li class="empty">无</li>'}</ul>
        {pub}
        """
    inner = f"""
    <h1>工作区</h1>
    <p class="muted">共享文章版本，而不是一个可互相覆盖的文本框。</p>
    <div class="grid">
      <div class="card"><h2 style="margin:0 0 8px;font-size:1.1rem">文章</h2>{"<ul>"+''.join(lis)+"</ul>" if lis else "<p class='empty'>还没有文章。</p>"}</div>
      <div class="card" style="grid-column:span 2">{detail}</div>
    </div>
    """
    return wrap(page_shell, "工作区", p, "/console/workspace", inner)


def access_page(page_shell, p) -> Response:
    acc = access_for(p)
    with connect() as conn:
        seen = conn.execute("SELECT * FROM last_seen WHERE identity_id=?", (p.id,)).fetchone()
        grants = conn.execute("SELECT agent_id, provider, roles, project_ids, version, revoked_at FROM agent_grants").fetchall() if acc.manage else []
    if acc.manage:
        ghtml = "".join(
            f"<tr><td>{html.escape(g['agent_id'])}</td><td>{html.escape(g['roles'])}</td><td>{html.escape(g['project_ids'])}</td>"
            f"<td>{'已撤销' if g['revoked_at'] else '有效'} v{g['version']}</td></tr>"
            for g in grants
        )
        table = f"<table><tr><th>Agent</th><th>角色</th><th>可写项目</th><th>状态</th></tr>{ghtml or '<tr><td colspan=4 class=empty>尚未授予任何 Agent 项目写权限。共享阅读不依赖此表。</td></tr>'}</table>"
    else:
        with connect() as conn:
            shared = [r["project_id"] for r in conn.execute("SELECT project_id FROM projects").fetchall() if acc.can_read_project(r["project_id"])]
        table = (
            f"<p>共享可读项目：{html.escape(', '.join(shared) or '（尚无共享项目）')}</p>"
            f"<p>可写项目：{html.escape(', '.join(acc.project_ids) or '无')}</p>"
            f"<p>范围：{html.escape(', '.join(sorted(acc.scopes)) or '无独立授权')}</p>"
        )
    inner = f"""
    <h1>接入与权限</h1>
    <p class="muted">最近鉴权请求：{html.escape(seen['last_seen_at'] if seen else '未知')} · 路径 {html.escape(seen['path'] if seen else '-')}</p>
    <section class="card">
      <p>HTML / Markdown / JSON：可用（本站点）</p>
      <p>私有鉴权：Bearer 或会话 Cookie</p>
      <p>MCP：仅只读查询工具。写入入口见 /api/v1/write-map。</p>
      <p>摘要生成：服务进程在到期后会尝试生成 08:00 / 20:00 快照；未到期或未生成的不算未读。外部供应商定时唤醒未接入——进程没在跑时不会补称已对齐。</p>
      <p>昨日晚间遗留：默认关闭，只在所有者打开后带未解决事项。</p>
      <p>写权限仍按项目成员关系；读权限：有效 token 可读全部共享项目。</p>
    </section>
    <section class="card" style="margin-top:16px">{table}</section>
    """
    return wrap(page_shell, "接入与权限", p, "/console/access", inner)


def publish_page(page_shell, p, *, err: str = "") -> Response:
    from hubv1 import publisher
    from hubv1 import workspace as wsmod

    acc = access_for(p)
    items = publisher.list_requests(acc)
    rows = []
    for it in items:
        rid = html.escape(it["request_id"])
        st = html.escape(str(it.get("state") or ""))
        repo = html.escape(f"{it.get('target_owner')}/{it.get('repo')}")
        actor = html.escape(str(it.get("actor_id") or ""))
        btns = ""
        if acc.manage and it.get("state") in {"awaiting_approval", "prepared"}:
            btns = (
                f"<form method='post' action='/console/publish/{rid}/approve' style='display:inline'>"
                f"<button type='submit'>批准</button></form> "
                f"<form method='post' action='/console/publish/{rid}/reject' style='display:inline'>"
                f"<button type='submit'>拒绝</button></form>"
            )
        rows.append(f"<tr><td>{rid}</td><td>{actor}</td><td>{repo}</td><td>{st}</td><td>{btns}</td></tr>")
    table = (
        "<table><tr><th>申请</th><th>申请人</th><th>仓库</th><th>状态</th><th></th></tr>"
        + ("".join(rows) or "<tr><td colspan=5 class=empty>没有发布申请。</td></tr>")
        + "</table>"
    )
    owners = publisher.allowed_owners()
    default_owner = owners[0] if owners else ""
    creds_ok = bool(publisher.load_github_token())
    enabled = publisher.publisher_enabled()
    can_request = enabled and (acc.has_scope("publish:request") or acc.manage)
    mine = wsmod.workspace_of(p.id) if acc.is_authed_reader() else None
    files = wsmod.list_files(mine["workspace_id"]) if mine else []
    boxes = "".join(
        f"<label style='display:block'><input type='checkbox' name='node_ids' value='{html.escape(f['node_id'])}'>"
        f" {html.escape(f.get('path') or f['name'])} ({int(f.get('size_bytes') or 0)} 字节)</label>"
        for f in files
    ) or "<p class='empty'>工作区还没有文件。请先在「我的工作区」上传 ZIP/TAR 或新建文本。</p>"
    if can_request:
        form = f"""
        <form method="post" action="/console/publish/requests">
          <p>从自己的工作区选择要公开的文件。ZIP/TAR 上传时已解压；仓库里是这些文件加上 MIT LICENSE。</p>
          {boxes}
          <p><label>GitHub 账号 <input name="target_owner" required maxlength="80" value="{html.escape(default_owner)}"></label></p>
          <p><label>新仓库名 <input name="repo" required maxlength="80" placeholder="例如 ncit-cyclegan-notes"></label></p>
          <p><label>分支 <input name="branch" maxlength="40" value="main"></label></p>
          <p><label><input type="checkbox" name="create_repo" value="1" checked> 创建新的公开仓库</label></p>
          <button type="submit">提交建仓发布申请</button>
        </form>
        """
    elif not enabled:
        form = "<p class='empty'>发布功能未打开。</p>"
    else:
        form = "<p class='empty'>当前身份没有 publish:request。Agent 不能自己批准。</p>"
    cred = (
        f"发布开关：{'开' if enabled else '关'} · "
        f"GitHub 凭据：{'已配置' if creds_ok else '未配置'} · "
        f"目标账号：{html.escape(', '.join(owners) or '未配置')} · "
        f"MIT 版权人：{html.escape(publisher.copyright_holder() or '未配置')}"
    )
    err_html = f"<p class='warn'>{html.escape(err)}</p>" if err else ""
    inner = f"""
    <h1>GitHub 发布</h1>
    <p class="muted">只能申请。批准后由 publisher 用独立凭据创建或推送公开仓库。申请人不能自己批准，也不能拿到 gh/shell。成绩单、证件、银行资料不要放进申请。</p>
    <p class="muted">{cred}</p>
    {err_html}
    <section class="card"><h2 style="margin:0 0 8px;font-size:1.1rem">新建发布申请</h2>{form}</section>
    <section class="card" style="margin-top:16px"><h2 style="margin:0 0 8px;font-size:1.1rem">申请列表</h2>{table}</section>
    """
    return wrap(page_shell, "发布", p, "/console/publish", inner)


def profile_page(page_shell, p) -> Response:
    acc = access_for(p)
    with connect() as conn:
        pubs = conn.execute("SELECT * FROM profiles WHERE kind='public' ORDER BY version DESC LIMIT 3").fetchall()
        cols = conn.execute("SELECT * FROM profiles WHERE kind='collab' ORDER BY version DESC LIMIT 3").fetchall()

    def block(title, rows, kind):
        if not rows:
            return f"<p class='empty'>{title}尚无草稿。</p>"
        latest = rows[0]
        pub = "已发布" if latest["published"] else "草稿未发布"
        hist = "".join(
            f"<li>v{r['version']} {html.escape(r['created_at'])} {'发布' if r['published'] else '草稿'} {html.escape(r['content_hash'][:12])}</li>"
            for r in rows
        )
        form = ""
        if acc.manage:
            form = f"""
            <form method="post" action="/console/profile/{kind}">
              <input type="hidden" name="expected_version" value="{latest['version']}">
              <input name="title" value="{html.escape(latest['title'])}" maxlength="160">
              <textarea name="body" maxlength="20000">{html.escape(latest['body'])}</textarea>
              <label><input type="checkbox" name="publish" value="1"> 发布这一版（公开简介会进公网；协作资料仅 token 可见）</label>
              <button type="submit">保存新版本</button>
            </form>
            """
        body_show = latest["body"] if acc.is_authed_reader() else ("公开简介尚未批准发布。" if kind == "public" else "尚无协作资料。")
        token_note = "持 token 可读，不上公网" if kind == "collab" else ("已上公网" if latest["published"] else "未上公网；持 token 的 Agent 可读这份草稿")
        return f"<h2>{html.escape(title)} · {pub} v{latest['version']}</h2><p class='muted'>{html.escape(token_note)}</p><pre class='diff'>{html.escape(body_show)}</pre><ul>{hist}</ul>{form}"

    inner = f"""
    <h1>两份资料</h1>
    <p class="muted">公开简介与协作资料分别编辑。协作资料给持 token 的 Agent 读即可，不必上公网。公开简介须单独批准才出现在 /about。证件与银行材料不会入库。</p>
    <section class="card">{block("公开简介", pubs, "public")}</section>
    <section class="card" style="margin-top:16px">{block("Agent 协作资料", cols, "collab")}</section>
    """
    return wrap(page_shell, "两份资料", p, "/console/profile", inner)
