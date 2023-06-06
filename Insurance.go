package main

import (
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// HealthInsuranceContract represents the smart contract
type HealthInsuranceContract struct {
	contractapi.Contract
}

// Policy represents the structure of an insurance policy
type Policy struct {
	PolicyID     string `json:"policyId"`
	HolderName   string `json:"holderName"`
	Premium      uint   `json:"premium"`
	TotalClaims  uint   `json:"totalClaims"`
	ClaimedAmount uint   `json:"claimedAmount"`
}

// InitLedger initializes the state with a few sample insurance policies
func (c *HealthInsuranceContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	policies := []Policy{
		{PolicyID: "POL001", HolderName: "John Doe", Premium: 500, TotalClaims: 0, ClaimedAmount: 0},
		{PolicyID: "POL002", HolderName: "Jane Smith", Premium: 750, TotalClaims: 0, ClaimedAmount: 0},
	}

	for _, policy := range policies {
		err := ctx.GetStub().PutState(policy.PolicyID, policyAsBytes(policy))
		if err != nil {
			return fmt.Errorf("failed to put policy %s: %w", policy.PolicyID, err)
		}
	}

	return nil
}

// CreatePolicy creates a new health insurance policy
func (c *HealthInsuranceContract) CreatePolicy(ctx contractapi.TransactionContextInterface, policyID string, holderName string, premium uint) error {
	existing, err := ctx.GetStub().GetState(policyID)
	if err != nil {
		return fmt.Errorf("failed to read policy %s: %w", policyID, err)
	}
	if existing != nil {
		return fmt.Errorf("policy %s already exists", policyID)
	}

	policy := Policy{
		PolicyID:     policyID,
		HolderName:   holderName,
		Premium:      premium,
		TotalClaims:  0,
		ClaimedAmount: 0,
	}

	err = ctx.GetStub().PutState(policyID, policyAsBytes(policy))
	if err != nil {
		return fmt.Errorf("failed to put policy %s: %w", policyID, err)
	}

	return nil
}

// GetPolicy retrieves a health insurance policy by its ID
func (c *HealthInsuranceContract) GetPolicy(ctx contractapi.TransactionContextInterface, policyID string) (*Policy, error) {
	policyBytes, err := ctx.GetStub().GetState(policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy %s: %w", policyID, err)
	}
	if policyBytes == nil {
		return nil, fmt.Errorf("policy %s does not exist", policyID)
	}

	policy := new(Policy)
	err = policyFromBytes(policyBytes, policy)
	if err != nil {
		return nil, err
	}

	return policy, nil
}

// ClaimPolicy claims an amount for a health insurance policy
func (c *HealthInsuranceContract) ClaimPolicy(ctx contractapi.TransactionContextInterface, policyID string, claimAmount uint) error {
	policy, err := c.GetPolicy(ctx, policyID)
	if err != nil {
		return err
	}

	policy.TotalClaims++
	policy.ClaimedAmount += claimAmount

	err = ctx.GetStub().PutState(policyID, policyAsBytes(*policy))
	if err != nil {
		return fmt.Errorf("failed to put policy %s: %w", policyID, err)
	}

	return nil
}

// Helper function to convert a policy to bytes
func policyAsBytes(policy Policy) ([]byte, error) {
	policyBytes, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy: %w", err)
	}
	return policyBytes, nil
}

// Helper function to convert bytes to a policy
func policyFromBytes(policyBytes []byte, policy *Policy) error {
	err := json.Unmarshal(policyBytes, policy)
	if err != nil {
		return fmt.Errorf("failed to unmarshal policy: %w", err)
	}
	return nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&HealthInsuranceContract{})
	if err != nil {
		fmt.Printf("Error creating HealthInsuranceContract chaincode: %s", err.Error())
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting HealthInsuranceContract chaincode: %s", err.Error())
	}
}