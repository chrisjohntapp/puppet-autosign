#!/usr/bin/ruby

require 'aws-sdk'
require 'json'
require 'fileutils'
require 'daemons'
require 'logger'
require 'signal'
require 'open3'

#==================================================================
# FUNCTIONS
#==================================================================

module PuppetError
  class Error < StandardError
    def initialize(msg='A system call to the puppet executable failed')
      super
    end
  end

  class ExecError < StandardError
    def initialize(msg="A system call to the puppet executable can't find the "\
                       'executable')
      super
    end
  end
end

module PuppetCert
  def self.remove(instance_hostname, logger)
    logger.debug('PuppetCert.remove received instance hostname: '\
                 "#{instance_hostname} and logger ref: #{logger}")
    begin
      Open3.popen3("puppet cert clean #{instance_hostname}") do | stdin,
      stdout, stderr, wait_thr |
        out = stdout.read
        err = stderr.read
        if wait_thr.value.success?
          logger.info("#{instance_hostname} cert revoked")
          logger.debug(out)
        else
          logger.error("'puppet cert clean #{instance_hostname}' failed")
          logger.error(out) unless out.empty?
          logger.error(err) unless err.empty?
          raise PuppetError::Error
        end
      end
    rescue PuppetError::Error => e
      raise e
    rescue => e
      logger.fatal('error while making system call to puppet binary. check '\
                   'executable path etc.')
      logger.fatal(e.message)
      logger.debug(e.backtrace)
      raise PuppetError::ExecError
    end
  end
end

module PuppetDB
  def self.remove(instance_hostname, logger)
    logger.debug('PuppetDB.remove received instance hostname: '\
                 "#{instance_hostname} and logger ref: #{logger}")
    begin
      Open3.popen3("puppet node deactivate #{instance_hostname}") do | stdin,
      stdout, stderr, wait_thr |
        out = stdout.read
        err = stderr.read
        if wait_thr.value.success?
          logger.debug(out)
          logger.info("#{instance_hostname} deactivated from PuppetDB")
        else
          logger.error("puppet node deactivate #{instance_hostname} failed")
          logger.error(out) unless out.empty?
          logger.error(err) unless err.empty?
          raise PuppetError::Error
        end
      end
    rescue PuppetError::Error => e
      raise e
    rescue => e
      logger.fatal('error while making system call to puppet binary. check '\
                   'executable path etc.')
      logger.fatal(e.message)
      logger.debug(e.backtrace)
      raise PuppetError::ExecError
    end
  end
end

module Whitelist
  def self.add(sqs, logger)
    logger.debug("Whitelist.add received sqs ref: #{sqs} and logger ref: "\
                 "#{logger}")
    # Poll queue & store messages in array.
    begin
      aresp = sqs.receive_message({
        max_number_of_messages: 10,
        queue_url: "https://sqs.#{ENV['AWS_REGION']}.amazonaws.com/"\
                   "#{ENV['AWS_ACCOUNT']}/#{ENV['SQS_PEND_QUEUE']}",
        visibility_timeout: 0,
        wait_time_seconds: 4,
      })
    rescue => e
      logger.warning('error while retrieving messages from SQS.')
      logger.warning(e.message)
      logger.debug(e.backtrace)
    end
    if aresp.messages.empty?
      logger.debug("no messages found in the #{ENV['SQS_PEND_QUEUE']} queue")
    else
      message_ids = Array.new
      aresp.messages.each do | msg |
        json = JSON.parse(msg.body)
        message_ids.push(json['id'])
      end
      logger.debug('found the following message ids in '\
                   "#{ENV['SQS_PEND_QUEUE']} queue: #{message_ids}")
    end

    # Iterate over messages using their instance-id.
    aresp.messages.each do | msg |
      json = JSON.parse(msg.body)
      instance_id = json['detail']['instance-id']
      message_id = json['id']
      logger.debug("instance id #{instance_id} found in "\
                   "#{ENV['SQS_PEND_QUEUE']} queue; message id: #{message_id}")
      # Set flag if instance id already present in whitelist.
      id_present = 'no'
      File.open("#{ENV['PUPPET_WHITELIST']}").each do | li |
        if (li.chomp[/.*#{instance_id[14..18]}\z/])
          id_present = 'yes'
          logger.debug("*.#{instance_id[14..18]} already present in whitelist")
          break
        else
          next
        end
      end
      # If id not found, add suitable glob to whitelist, and log addition.
      if id_present == 'no'
        logger.debug("*.#{instance_id[14..18]} not found in whitelist")
        fh = File.open("#{ENV['PUPPET_WHITELIST']}", "a")
        fh.puts "*.#{instance_id[14..18]}"
        fh.close
        logger.info("*.#{instance_id[14..18]} added to whitelist")
      end

      # Delete the message from queue.
      begin
        sqs.delete_message({
          queue_url: "https://sqs.#{ENV['AWS_REGION']}.amazonaws.com/"\
                     "#{ENV['AWS_ACCOUNT']}/#{ENV['SQS_PEND_QUEUE']}",
          receipt_handle: msg.receipt_handle,
        })
      rescue => e
        logger.warning('error while deleting message from SQS.')
        logger.warning(e.message)
        logger.backtrace(e.backtrace)
      end
      logger.debug("message #{msg.message_id.to_s} deleted from "\
                   "#{ENV['SQS_PEND_QUEUE']} queue")
    end
  end

  def self.remove(sqs, logger)
    logger.debug("Whitelist.remove received sqs ref: #{sqs} and logger ref: "\
                 "#{logger}")
    # Poll queue; store messages in array.
    begin
      rresp = sqs.receive_message({
        max_number_of_messages: 10,
        queue_url: "https://sqs.#{ENV['AWS_REGION']}.amazonaws.com/"\
                   "#{ENV['AWS_ACCOUNT']}/#{ENV['SQS_TERM_QUEUE']}",
        visibility_timeout: 0,
        wait_time_seconds: 4,
      })
    rescue => e
      logger.warning('error while retrieving messages from SQS.')
      logger.warning(e.message)
      logger.backtrace(e.backtrace)
    end
    if rresp.messages.empty?
      logger.debug("no messages found in the #{ENV['SQS_TERM_QUEUE']} queue")
    else
      message_ids = Array.new
      rresp.messages.each do | msg |
        json = JSON.parse(msg.body)
        message_ids.push(json['id'])
      end
      logger.debug('found the following message ids in '\
                   "#{ENV['SQS_TERM_QUEUE']} queue: #{message_ids}")
    end

    # Iterate over messages using their instance-id.
    decommissions = Array.new
    log_messages = Array.new
    rresp.messages.each do | msg |
      json = JSON.parse(msg.body)
      instance_id = json['detail']['instance-id']
      message_id = json['id']
      logger.debug("instance id #{instance_id} found in "\
                   "#{ENV['SQS_TERM_QUEUE']} queue; message id: #{message_id}")

      # Remove instance id glob from whitelist.
      # Create tmp file containing all values NOT matching current id glob.
      tmp_file = Tempfile.new("#{File.basename($0)}")
      File.open(tmp_file, 'w') do | out_file |
        File.foreach(ENV['PUPPET_WHITELIST']) do | li |
          out_file.puts li unless li.chomp[/.*#{instance_id[14..18]}\z/]
          logger.debug("#{li.chomp} retained in whitelist")
        end
      end
      # Overwrite whitelist with tmp file.
      if File.file?(tmp_file)
        FileUtils.mv(tmp_file, ENV['PUPPET_WHITELIST'])
        logger.debug("#{ENV['PUPPET_WHITELIST']} updated")
      end

      # Add current instance to array of hostnames to be decommissioned.
      begin
        instance_hostname = `puppet cert list --all -H | grep \
                             #{instance_id[14..18]} | tr -d '"+\ '`.chomp
        logger.debug("puppet cert for #{instance_hostname} found") unless \
          instance_hostname.empty?
      rescue => e
        logger.fatal('error while making system call to puppet binary. check '\
                     'executable path etc.')
        logger.fatal(e.message)
        logger.debug(e.backtrace)
        raise PuppetError::ExecError
      end
      unless instance_hostname.empty?
        decommissions.push(instance_hostname.to_s)
        logger.debug("#{instance_hostname.to_s} added to list of nodes to be "\
                     'decommissioned')
      end

      # Add instance id to array of removed ids.
      log_messages.push(instance_id[14..18].to_s)

      # Delete the current message from the queue.
      sqs.delete_message({
        queue_url: "https://sqs.#{ENV['AWS_REGION']}.amazonaws.com/"\
                   "#{ENV['AWS_ACCOUNT']}/#{ENV['SQS_TERM_QUEUE']}",
        receipt_handle: msg.receipt_handle,
      })
      logger.debug("message #{msg.message_id.to_s} deleted from "\
                   "#{ENV['SQS_TERM_QUEUE']} queue")
    end

    # Remove dupes and decommission nodes.
    u_decommissions = decommissions.uniq
    u_decommissions.each do | d |
      begin
        logger.debug('calling PuppetCert.remove')
        PuppetCert.remove(d, logger)
      rescue PuppetError::Error => e
        logger.error(e.message)
        logger.error('PuppetCert.remove failed. This is not currently treated '\
                     'as fatal but likely will be in future')
      end
      begin
        logger.debug('calling PuppetDB.remove')
        PuppetDB.remove(d, logger)
      rescue PuppetError::Error => e
        logger.error(e.message)
        logger.error('PuppetDB.remove failed. This is not currently treated '\
                     'as fatal but likely will be in future')
      end
    end

    # Remove dupes and log removed node id's.
    u_log_messages = log_messages.uniq
    u_log_messages.each do | l |
      logger.info("*.#{l} removed from whitelist")
    end
  end
end

def shut_down(logger)
  logger.debug("shut_down received logger ref: #{logger}")
  logger.info("shutting down process pid: #{$$}")
  sleep 3
  exit
end

def run_once(sqs, logger)
  logger.debug("run_once received sqs ref: #{sqs} and logger ref: #{logger}")
  logger.info("'onetime' is set to true, so running through once then exiting")
  logger.debug('calling Whitelist.add')
  Whitelist.add(sqs, logger)
  logger.debug('calling Whitelist.remove')
  Whitelist.remove(sqs, logger)
  exit
end

def run_forever(sqs, logger, run_interval)
  logger.debug("run_forever received sqs ref: #{sqs}, logger ref: #{logger} "\
               "and run_interval: #{run_interval} seconds")
  logger.info('entering main loop. SIGTERM will terminate')
  catch :sigterm do
    loop do
      logger.debug('calling Whitelist.add')
      Whitelist.add(sqs, logger)
      logger.debug('calling Whitelist.remove')
      Whitelist.remove(sqs, logger)
      logger.debug("sleeping #{run_interval} seconds")
      if Time.now.min % 10 == 0
        logger.info("I'm alive")
      end
      sleep(run_interval)
    end
  end
  logger.info('received SIGTERM')
  shut_down(logger)
end

#==================================================================
# MAIN
#==================================================================

# Debugging switches.
run_in_foreground = false # Avoid daemonizing.
one_time = false # Avoid entering a loop -- just poll each queue once then exit.
run_interval = 12 # Seconds sleep between polling queues.

daemonize_options = {
  :app_name   => "#{File.basename($0)}",
  :ontop      => false,
  :backtrace  => true,
  :dir_mode   => :normal,
  :dir        => '/var/run',
  :log_output => false # This is handled by logger instead.
}
Daemons.daemonize(daemonize_options) unless run_in_foreground

logger = Logger.new(ENV['LOG_FILE'], 5, 1024000)
logger.progname = "#{File.basename($0)}"
logger.info("starting up with process pid: #{$$}")

case ENV['LOG_LEVEL']
when 'UNKNOWN' then logger.level = Logger::UNKNOWN
when 'FATAL'   then logger.level = Logger::FATAL
when 'ERROR'   then logger.level = Logger::ERROR
when 'WARN'    then logger.level = Logger::WARN
when 'INFO'    then logger.level = Logger::INFO
when 'DEBUG'   then logger.level = Logger::DEBUG
else logger.level = Logger::ERROR
end
logger.info("log level set to #{ENV['LOG_LEVEL']}")

sqs = Aws::SQS::Client.new
logger.debug("created sqs connection #{sqs}")

Signal.trap('SIGTERM') { throw :sigterm }

if one_time
  run_once(sqs, logger)
else
  run_forever(sqs, logger, run_interval)
end

