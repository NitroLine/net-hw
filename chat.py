#!/usr/bin/env python3
import json

from aiohttp import web


class WSChat:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.conns = {}

    async def main_page(self, request):
        return web.FileResponse('./index.html')

    async def wshandler(self, request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        try:
            async for msg in ws:
                if msg.type == web.WSMsgType.text:
                    if msg.data == 'ping':
                        await ws.send_str('pong')
                    else:
                        data = json.loads(msg.data)
                        if data['mtype'] == 'INIT':
                            await self.user_joined(data['id'], ws)
                        elif data['mtype'] == 'TEXT':
                            await self.onmessage(data)
                elif msg.type == web.WSMsgType.close:
                    break
        finally:
            await self.user_left(ws)
        return ws

    async def onmessage(self, data):
        for_all = data['to'] is None
        msg = json.dumps({'mtype': 'MSG' if for_all else 'DM',
                          'id': data['id'],
                          'text': data['text']})
        if for_all:
            await self.send_to_others(msg, data['id'])
        else:
            if data['to'] in self.conns and data['to'] != data['id']:
                await self.conns[data['to']].send_str(msg)

    async def user_left(self, ws):
        user_id = None
        for conn_id, conn in self.conns.items():
            if ws == conn:
                user_id = conn_id
                break
        if user_id is None:
            return
        del self.conns[user_id]
        msg = json.dumps({'mtype': 'USER_LEAVE',
                          'id': user_id})
        await self.send_to_others(msg, user_id)

    async def user_joined(self, user_id, ws):
        msg = json.dumps({'mtype': 'USER_ENTER',
                          'id': user_id})
        await self.send_to_others(msg)
        self.conns[user_id] = ws

    async def send_to_others(self, msg, sender_id=None):
        for id in self.conns:
            if id != sender_id:
                await self.conns[id].send_str(msg)

    def run(self):
        app = web.Application()
        app.router.add_get('/', self.main_page)
        app.router.add_get('/chat', self.wshandler)
        web.run_app(app, host=self.host, port=self.port)


if __name__ == '__main__':
    WSChat().run()
