# frozen_string_literal: true

class Api::V2::Accounts::RelationshipsController < Api::V1::Accounts::RelationshipsController
  def index
    accounts = Account.where(id: account_ids).select('id')
    # .where doesn't guarantee that our results are in the same order
    # we requested them, so return the "right" order to the requestor.
    @accounts = accounts.index_by(&:id).values_at(*account_ids).compact
    render json: @accounts, each_serializer: REST::RelationshipSerializer, relationships: relationships
  end
end
