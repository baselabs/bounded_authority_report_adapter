defmodule BoundedAuthorityReportAdapter.OptionalCallbacks do
  @moduledoc false
  # Which entry points call each optional key-handle callback, so require it. The doctor's
  # advisories are built from this list; test/bounded_authority_report_adapter/
  # optional_callback_users_test.exs derives the same map by calling every shipped sign_*/3
  # (with and without each option it accepts) through a handle that records its callbacks,
  # so this cannot drift from the code.

  alias BoundedAuthorityReportAdapter.V3

  @spec users() :: [{atom(), [{module(), atom()}]}]
  def users do
    [
      key_identity: [
        {BoundedAuthorityReportAdapter, :sign_anchor},
        {BoundedAuthorityReportAdapter, :sign_key_transition},
        {BoundedAuthorityReportAdapter, :sign_content_assertion},
        {V3, :sign_anchor},
        {V3, :sign_key_transition}
      ],
      signing_identity: [{BoundedAuthorityReportAdapter, :sign_grant}, {V3, :sign_grant}]
    ]
  end
end
