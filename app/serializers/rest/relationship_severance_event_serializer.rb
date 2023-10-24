# frozen_string_literal: true

class REST::RelationshipSeveranceEventSerializer < ActiveModel::Serializer
  attributes :id, :type, :domain, :created_at

  def id
    object.id.to_s
  end
end
