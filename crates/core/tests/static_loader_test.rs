#[cfg(test)]
mod vars_parsing {
    use weituo_core::static_loader;

    #[test]
    fn yaml_vars_are_loaded_into_rule_entry() {
        let yaml = r#"
contracts:
  - address: "0xcontract"
    chain_id: 1
    allowlist:
      - func: "transfer(address,uint256)"
        expr: "args.to == vars.USDT"
        vars:
          USDT: "0xdac17f"
          ETH:  "0xeeee"
"#;
        let dir = tempfile::tempdir().unwrap();
        let yaml_path = dir.path().join("waf.yaml");
        std::fs::write(&yaml_path, yaml).unwrap();
        let abi_dir = dir.path().to_str().unwrap();

        let (_, contracts) = static_loader::load(yaml_path.to_str().unwrap(), abi_dir, 1).unwrap();

        let selector = static_loader::selector_for("transfer(address,uint256)");
        let entry = contracts
            .get(&(1, "0xcontract".to_string()))
            .and_then(|m| m.get(&selector))
            .expect("rule should be loaded");

        let vars = &entry.clauses[0].vars;
        assert_eq!(
            vars.get("USDT").and_then(|v| v.as_str()),
            Some("0xdac17f"),
            "USDT var should be loaded"
        );
        assert_eq!(
            vars.get("ETH").and_then(|v| v.as_str()),
            Some("0xeeee"),
            "ETH var should be loaded"
        );
    }

    #[test]
    fn yaml_rule_without_vars_has_empty_vars_map() {
        let yaml = r#"
contracts:
  - address: "0xcontract"
    chain_id: 1
    allowlist:
      - func: "transfer(address,uint256)"
        expr: "args.amount > 0"
"#;
        let dir = tempfile::tempdir().unwrap();
        let yaml_path = dir.path().join("waf.yaml");
        std::fs::write(&yaml_path, yaml).unwrap();
        let abi_dir = dir.path().to_str().unwrap();

        let (_, contracts) = static_loader::load(yaml_path.to_str().unwrap(), abi_dir, 1).unwrap();

        let selector = static_loader::selector_for("transfer(address,uint256)");
        let entry = contracts
            .get(&(1, "0xcontract".to_string()))
            .and_then(|m| m.get(&selector))
            .expect("rule should be loaded");

        assert!(
            entry.clauses[0].vars.is_empty(),
            "no vars in YAML = empty map"
        );
    }
}
