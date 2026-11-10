"""Add an opt-in matrix control to a pinned PhantomView frontend revision."""

import hashlib

SOURCE_SHA256 = "0c0a5f2d6bee187e2c4dff9185676df7996dcb9573f9cf77bad038abf20ca02c"
ANCHOR = "function documents(){const ds="
NOTICE = (
    'return `<div class="notice">${uiText("Document tree registered in PhantomDocs.'
)
SCRIPT_ANCHOR = "document.addEventListener('input',e=>{if(e.target.id==='kb-search')"
SCOPED_SOURCE_SHA256 = (
    "38f451f5cd9544dd2d578902b1fc7eda5828f0a8fad3c2f48371f4df272f9c1a"
)
SCOPED_ANCHOR = "    if(!records.childElementCount)records.append("


def patch_ui(source):
    """Return candidate bytes; the endpoint remains independently authorized."""
    if (
        not isinstance(source, bytes)
        or hashlib.sha256(source).hexdigest() != SOURCE_SHA256
    ):
        raise ValueError("unsupported viewer revision")
    text = source.decode("utf-8")
    if any(text.count(anchor) != 1 for anchor in (ANCHOR, NOTICE, SCRIPT_ANCHOR)):
        raise ValueError("viewer composition changed")
    text = text.replace(
        NOTICE,
        'return `<section class="panel"><h3>${uiText("Project matrix")}</h3>'
        '<button class="button" data-matrix-current>${uiText("Open current matrix")}</button>'
        '</section><div class="notice">${uiText("Document tree registered in PhantomDocs.',
        1,
    )
    text = text.replace(
        SCRIPT_ANCHOR,
        "document.addEventListener('click',async e=>{if(!e.target.closest('[data-matrix-current]'))return;"
        "const dialog=$('#note'),body=$('#note-body');body.textContent=uiText('Reading matrix…');"
        "if(!dialog.open)dialog.showModal();try{const data=await api('/api/matrix/current');"
        "const title=document.createElement('h2'),pre=document.createElement('pre');"
        "title.textContent=uiText('Project matrix');pre.className='kb-content';"
        "pre.textContent=data.content;body.replaceChildren(title,pre);}"
        "catch(e){body.textContent=uiText('Matrix unavailable');}});\n" + SCRIPT_ANCHOR,
        1,
    )
    return text.encode("utf-8")


def patch_scoped_ui(source):
    """Add the matrix control to the identified, scoped viewer revision."""
    if (
        not isinstance(source, bytes)
        or hashlib.sha256(source).hexdigest() != SCOPED_SOURCE_SHA256
    ):
        raise ValueError("unsupported scoped viewer revision")
    content = source.decode("utf-8")
    if content.count(SCOPED_ANCHOR) != 1:
        raise ValueError("scoped viewer composition changed")
    addition = (
        "    if(!search&&selected?.kind==='document'){\n"
        "      const button=text('button','Open current matrix','card');button.type='button';\n"
        "      button.addEventListener('click',async()=>{\n"
        "        const ticket=epoch,detailTicket=++detailEpoch;\n"
        "        $('detail-title').textContent='Project matrix';\n"
        "        $('detail-content').textContent='Reading matrix…';\n"
        "        if(!$('detail').open)$('detail').showModal();\n"
        "        try{const data=await api('/api/matrix/current',undefined,controller.signal);\n"
        "          if(ticket!==epoch||detailTicket!==detailEpoch||!$('detail').open)return;\n"
        "          if(typeof data.content!=='string')throw Error('Matrix unavailable');\n"
        "          $('detail-content').replaceChildren(text('pre',data.content,'profile-document-body'));\n"
        "        }catch(error){if(ticket===epoch&&detailTicket===detailEpoch&&$('detail').open)"
        "$('detail-content').textContent='Matrix unavailable';}\n"
        "      });records.prepend(button);\n"
        "    }\n"
    )
    return content.replace(SCOPED_ANCHOR, addition + SCOPED_ANCHOR, 1).encode("utf-8")
