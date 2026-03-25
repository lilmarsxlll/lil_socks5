import asyncio
import socket
import struct

from src.const import MAX_CONNECTIONS, BUFFER_SIZE, CONNECTION_TIMEOUT
from src.logging_config import get_logger, setup_logging

setup_logging()
logger = get_logger(__name__)


sem = asyncio.Semaphore(MAX_CONNECTIONS)


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Проксирует данные между клиентом и сервером
    Attributes:
        reader - откуда читаем данные (клиент)
        writer - куда отправляем данные (сервер)
    """
    try:
        while True:
            data = await asyncio.wait_for(
                reader.read(BUFFER_SIZE), timeout=CONNECTION_TIMEOUT
            )
            if not data:
                logger.info("No data, closing pipe connection.")
                break
            writer.write(data)
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionResetError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()
        logger.info("Closing pipe connection.")


async def handle_socks5(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, initial_byte: bytes
):
    """Получает соединение от клиента, устанавливает соединение с конечным сервером и проксирует данные
    Attributes:
        reader - откуда читаем данные (клиент)
        writer - куда отправляем данные (сервер)
        initial_byte - первый байт, который прислал клиент (определение версии протокола клиента и типа соединения)
    """
    try:
        data = initial_byte + await reader.read(1)
        ver, nmethods = struct.unpack("!BB", data)
        logger.debug(f"Version: {ver}, Methods: {nmethods}")
        await reader.read(nmethods)

        writer.write(b"\x05\x00")
        await writer.drain()

        header = await asyncio.wait_for(
            reader.readexactly(4), timeout=CONNECTION_TIMEOUT
        )
        ver, cmd, _, atyp = struct.unpack("!BBBB", header)

        if atyp == 1:
            addr_bytes = await reader.readexactly(4)
            address = socket.inet_ntoa(addr_bytes)
        elif atyp == 3:
            length = (await reader.readexactly(1))[0]
            address = (await reader.readexactly(length)).decode()
        elif atyp == 4:
            addr_bytes = await reader.readexactly(16)
            address = socket.inet_ntop(socket.AF_INET6, addr_bytes)
        else:
            logger.warning(f"Unknown address type: {atyp}")
            writer.close()
            await writer.wait_closed()
            return

        port_bytes = await reader.readexactly(2)
        port = struct.unpack("!H", port_bytes)[0]

        remote_reader, remote_writer = await asyncio.open_connection(address, port)
        logger.info(f"Connected to {address}:{port}")

        writer.write(struct.pack("!BBBB4sH", 5, 0, 0, 1, b"\x00\x00\x00\x00", 0))
        await writer.drain()

        task1 = asyncio.create_task(pipe(reader, remote_writer))
        task2 = asyncio.create_task(pipe(remote_reader, writer))

        done, pending = await asyncio.wait(
            [task1, task2], return_when=asyncio.FIRST_COMPLETED
        )

        for task in pending:
            task.cancel()

        await asyncio.gather(*pending, return_exceptions=True)

        logger.info(f"Connection with {address}:{port} finished.")

    except Exception as e:
        logger.error(f"Error: {e}")
        writer.close()
        await writer.wait_closed()


async def conn_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Обработчик каждого входящего сообщения на прокси
    Attributes:
        reader - откуда читаем данные (клиент)
        writer - куда отправляем данные (сервер)
    """
    async with sem:
        try:
            initial_byte = await asyncio.wait_for(
                reader.read(1), timeout=CONNECTION_TIMEOUT
            )
            if not initial_byte:
                writer.close()
                await writer.wait_closed()
                return

            if initial_byte[0] == 0x05:
                logger.info("User using SOCKS5 proxy.")
                await handle_socks5(reader, writer, initial_byte)
            else:
                logger.warning(f"Unknown address protocol: {initial_byte[0]}")
                writer.close()
                await writer.wait_closed()
        except Exception:
            logger.exception("Connection error.")
            writer.close()
            await writer.wait_closed()
            logger.info("Connection closed.")


async def main():
    server = await asyncio.start_server(conn_handler, "0.0.0.0", 1080)
    logger.info("SOCKS5 proxy started on 0.0.0.0:1080.")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("SOCKS 5 proxy stopped by user.")
