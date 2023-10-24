# frozen_string_literal: true

class SeveredRelationshipsController < ApplicationController
  layout 'admin'

  before_action :authenticate_user!
  before_action :set_body_classes
  before_action :set_cache_headers

  before_action :set_event, only: [:following, :followers]

  def index
    @events = RelationshipSeveranceEvent.about_account(current_account)
  end

  def following
    respond_to do |format|
      format.csv { send_data following_data, filename: 'following-TODO.csv' }
    end
  end

  def followers
    respond_to do |format|
      format.csv { send_data followers_data, filename: 'followers-TODO.csv' }
    end
  end

  private

  def set_event
    @event = RelationshipSeveranceEvent.find(params[:id])
  end

  def following_data
    CSV.generate(headers: ['Account address', 'Show boosts', 'Notify on new posts', 'Languages'], write_headers: true) do |csv|
      @event.severed_relationships.where(account: current_account).includes(:target_account).reorder(id: :desc).each do |follow|
        csv << [acct(follow.target_account), follow.show_reblogs, follow.notify, follow.languages&.join(', ')]
      end
    end
  end

  def followers_data
    CSV.generate(headers: ['Account address'], write_headers: true) do |csv|
      @event.severed_relationships.where(target_account: current_account).includes(:account).reorder(id: :desc).each do |follow|
        csv << [acct(follow.account)]
      end
    end
  end

  def acct(account)
    account.local? ? account.local_username_and_domain : account.acct
  end

  def set_body_classes
    @body_classes = 'admin'
  end

  def set_cache_headers
    response.cache_control.replace(private: true, no_store: true)
  end
end
