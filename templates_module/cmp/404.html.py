# -*- coding:utf-8 -*-
from mako import runtime, filters, cache
UNDEFINED = runtime.UNDEFINED
__M_dict_builtin = dict
__M_locals_builtin = locals
_magic_number = 10
_modified_time = 1544159742.299118
_enable_loop = True
_template_filename = '/vagrant/cmp/templates/404.html'
_template_uri = '404.html'
_source_encoding = 'utf-8'
_exports = []


def render_body(context,**pageargs):
    __M_caller = context.caller_stack._push_frame()
    try:
        __M_locals = __M_dict_builtin(pageargs=pageargs)
        __M_writer = context.writer()
        __M_writer(u'<!DOCTYPE html>\r\n<html xmlns="http://www.w3.org/1999/xhtml">\r\n<head>\r\n<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />\r\n<title>\u9875\u9762\u627e\u4e0d\u5230\uff08404\u9875\uff09</title>\r\n<link href="/static/css/base.min.css?v=1.0.1" rel="stylesheet" type="text/css"/>\r\n<style type="text/css">\r\n    body {\r\n        min-width: initial !important;\r\n        background: none;\r\n    }\r\n</style>\r\n</head>\r\n\r\n<body style="font-family:Microsoft Yahei;" class="king-errorpage-middle">\r\n    <!--HTML-->\r\n    <div class="king-exception-box king-500-page">\r\n        <img src="/static/img/error/404.png">\r\n        <h1>\u9875\u9762\u627e\u4e0d\u5230\u4e86</h1>\r\n    </div>\r\n</body>\r\n</html>\r\n')
        return ''
    finally:
        context.caller_stack._pop_frame()


"""
__M_BEGIN_METADATA
{"source_encoding": "utf-8", "line_map": {"26": 20, "20": 1, "15": 0}, "uri": "404.html", "filename": "/vagrant/cmp/templates/404.html"}
__M_END_METADATA
"""
