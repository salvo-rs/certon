#[test]
fn a_late_user_agent_does_not_disagree_with_the_client() {
    certon::http::client().unwrap();
    let original = certon::http::user_agent();
    certon::http::set_user_agent("too-late");
    assert_eq!(certon::http::user_agent(), original);
}
