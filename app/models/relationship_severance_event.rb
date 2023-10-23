# frozen_string_literal: true

# == Schema Information
#
# Table name: relationship_severance_events
#
#  id         :bigint(8)        not null, primary key
#  type       :integer          not null
#  created_at :datetime         not null
#  updated_at :datetime         not null
#
class RelationshipSeveranceEvent < ApplicationRecord
  self.inheritance_column = nil

  has_many :severed_relationships, inverse_of: :relationship_severance_event, dependent: :delete_all

  enum type: {
    domain_block: 0,
    user_domain_block: 1,
  }

  scope :about_account, ->(account) { where(id: SeveredRelationship.about_account(account).select(:relationship_severance_event_id)) }

  def import_from_follows!(follows)
    SeveredRelationship.insert_all( # rubocop:disable Rails/SkipsModelValidations
      follows.pluck(:account_id, :target_account_id, :show_reblogs, :notify, :languages).map do |account_id, target_account_id, show_reblogs, notify, languages|
        {
          account_id: account_id,
          target_account_id: target_account_id,
          show_reblogs: show_reblogs,
          notify: notify,
          languages: languages,
          relationship_severance_event_id: id,
        }
      end
    )
  end
end
