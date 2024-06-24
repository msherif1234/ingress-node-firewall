//go:build !ignore_autogenerated

/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressNodeFirewall) DeepCopyInto(out *IngressNodeFirewall) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressNodeFirewall.
func (in *IngressNodeFirewall) DeepCopy() *IngressNodeFirewall {
	if in == nil {
		return nil
	}
	out := new(IngressNodeFirewall)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IngressNodeFirewall) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressNodeFirewallConfig) DeepCopyInto(out *IngressNodeFirewallConfig) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressNodeFirewallConfig.
func (in *IngressNodeFirewallConfig) DeepCopy() *IngressNodeFirewallConfig {
	if in == nil {
		return nil
	}
	out := new(IngressNodeFirewallConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IngressNodeFirewallConfig) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressNodeFirewallConfigList) DeepCopyInto(out *IngressNodeFirewallConfigList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IngressNodeFirewallConfig, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressNodeFirewallConfigList.
func (in *IngressNodeFirewallConfigList) DeepCopy() *IngressNodeFirewallConfigList {
	if in == nil {
		return nil
	}
	out := new(IngressNodeFirewallConfigList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IngressNodeFirewallConfigList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressNodeFirewallConfigSpec) DeepCopyInto(out *IngressNodeFirewallConfigSpec) {
	*out = *in
	if in.NodeSelector != nil {
		in, out := &in.NodeSelector, &out.NodeSelector
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.Debug != nil {
		in, out := &in.Debug, &out.Debug
		*out = new(bool)
		**out = **in
	}
	if in.EBPFProgramManagerMode != nil {
		in, out := &in.EBPFProgramManagerMode, &out.EBPFProgramManagerMode
		*out = new(bool)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressNodeFirewallConfigSpec.
func (in *IngressNodeFirewallConfigSpec) DeepCopy() *IngressNodeFirewallConfigSpec {
	if in == nil {
		return nil
	}
	out := new(IngressNodeFirewallConfigSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressNodeFirewallConfigStatus) DeepCopyInto(out *IngressNodeFirewallConfigStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]v1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressNodeFirewallConfigStatus.
func (in *IngressNodeFirewallConfigStatus) DeepCopy() *IngressNodeFirewallConfigStatus {
	if in == nil {
		return nil
	}
	out := new(IngressNodeFirewallConfigStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressNodeFirewallICMPRule) DeepCopyInto(out *IngressNodeFirewallICMPRule) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressNodeFirewallICMPRule.
func (in *IngressNodeFirewallICMPRule) DeepCopy() *IngressNodeFirewallICMPRule {
	if in == nil {
		return nil
	}
	out := new(IngressNodeFirewallICMPRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressNodeFirewallList) DeepCopyInto(out *IngressNodeFirewallList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IngressNodeFirewall, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressNodeFirewallList.
func (in *IngressNodeFirewallList) DeepCopy() *IngressNodeFirewallList {
	if in == nil {
		return nil
	}
	out := new(IngressNodeFirewallList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IngressNodeFirewallList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressNodeFirewallNodeState) DeepCopyInto(out *IngressNodeFirewallNodeState) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressNodeFirewallNodeState.
func (in *IngressNodeFirewallNodeState) DeepCopy() *IngressNodeFirewallNodeState {
	if in == nil {
		return nil
	}
	out := new(IngressNodeFirewallNodeState)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IngressNodeFirewallNodeState) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressNodeFirewallNodeStateList) DeepCopyInto(out *IngressNodeFirewallNodeStateList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IngressNodeFirewallNodeState, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressNodeFirewallNodeStateList.
func (in *IngressNodeFirewallNodeStateList) DeepCopy() *IngressNodeFirewallNodeStateList {
	if in == nil {
		return nil
	}
	out := new(IngressNodeFirewallNodeStateList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IngressNodeFirewallNodeStateList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressNodeFirewallNodeStateSpec) DeepCopyInto(out *IngressNodeFirewallNodeStateSpec) {
	*out = *in
	if in.InterfaceIngressRules != nil {
		in, out := &in.InterfaceIngressRules, &out.InterfaceIngressRules
		*out = make(map[string][]IngressNodeFirewallRules, len(*in))
		for key, val := range *in {
			var outVal []IngressNodeFirewallRules
			if val == nil {
				(*out)[key] = nil
			} else {
				inVal := (*in)[key]
				in, out := &inVal, &outVal
				*out = make([]IngressNodeFirewallRules, len(*in))
				for i := range *in {
					(*in)[i].DeepCopyInto(&(*out)[i])
				}
			}
			(*out)[key] = outVal
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressNodeFirewallNodeStateSpec.
func (in *IngressNodeFirewallNodeStateSpec) DeepCopy() *IngressNodeFirewallNodeStateSpec {
	if in == nil {
		return nil
	}
	out := new(IngressNodeFirewallNodeStateSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressNodeFirewallNodeStateStatus) DeepCopyInto(out *IngressNodeFirewallNodeStateStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressNodeFirewallNodeStateStatus.
func (in *IngressNodeFirewallNodeStateStatus) DeepCopy() *IngressNodeFirewallNodeStateStatus {
	if in == nil {
		return nil
	}
	out := new(IngressNodeFirewallNodeStateStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressNodeFirewallProtoRule) DeepCopyInto(out *IngressNodeFirewallProtoRule) {
	*out = *in
	out.Ports = in.Ports
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressNodeFirewallProtoRule.
func (in *IngressNodeFirewallProtoRule) DeepCopy() *IngressNodeFirewallProtoRule {
	if in == nil {
		return nil
	}
	out := new(IngressNodeFirewallProtoRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressNodeFirewallProtocolRule) DeepCopyInto(out *IngressNodeFirewallProtocolRule) {
	*out = *in
	in.ProtocolConfig.DeepCopyInto(&out.ProtocolConfig)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressNodeFirewallProtocolRule.
func (in *IngressNodeFirewallProtocolRule) DeepCopy() *IngressNodeFirewallProtocolRule {
	if in == nil {
		return nil
	}
	out := new(IngressNodeFirewallProtocolRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressNodeFirewallRules) DeepCopyInto(out *IngressNodeFirewallRules) {
	*out = *in
	if in.SourceCIDRs != nil {
		in, out := &in.SourceCIDRs, &out.SourceCIDRs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.FirewallProtocolRules != nil {
		in, out := &in.FirewallProtocolRules, &out.FirewallProtocolRules
		*out = make([]IngressNodeFirewallProtocolRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressNodeFirewallRules.
func (in *IngressNodeFirewallRules) DeepCopy() *IngressNodeFirewallRules {
	if in == nil {
		return nil
	}
	out := new(IngressNodeFirewallRules)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressNodeFirewallSpec) DeepCopyInto(out *IngressNodeFirewallSpec) {
	*out = *in
	in.NodeSelector.DeepCopyInto(&out.NodeSelector)
	if in.Ingress != nil {
		in, out := &in.Ingress, &out.Ingress
		*out = make([]IngressNodeFirewallRules, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Interfaces != nil {
		in, out := &in.Interfaces, &out.Interfaces
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressNodeFirewallSpec.
func (in *IngressNodeFirewallSpec) DeepCopy() *IngressNodeFirewallSpec {
	if in == nil {
		return nil
	}
	out := new(IngressNodeFirewallSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressNodeFirewallStatus) DeepCopyInto(out *IngressNodeFirewallStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressNodeFirewallStatus.
func (in *IngressNodeFirewallStatus) DeepCopy() *IngressNodeFirewallStatus {
	if in == nil {
		return nil
	}
	out := new(IngressNodeFirewallStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressNodeProtocolConfig) DeepCopyInto(out *IngressNodeProtocolConfig) {
	*out = *in
	if in.TCP != nil {
		in, out := &in.TCP, &out.TCP
		*out = new(IngressNodeFirewallProtoRule)
		**out = **in
	}
	if in.UDP != nil {
		in, out := &in.UDP, &out.UDP
		*out = new(IngressNodeFirewallProtoRule)
		**out = **in
	}
	if in.SCTP != nil {
		in, out := &in.SCTP, &out.SCTP
		*out = new(IngressNodeFirewallProtoRule)
		**out = **in
	}
	if in.ICMP != nil {
		in, out := &in.ICMP, &out.ICMP
		*out = new(IngressNodeFirewallICMPRule)
		**out = **in
	}
	if in.ICMPv6 != nil {
		in, out := &in.ICMPv6, &out.ICMPv6
		*out = new(IngressNodeFirewallICMPRule)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressNodeProtocolConfig.
func (in *IngressNodeProtocolConfig) DeepCopy() *IngressNodeProtocolConfig {
	if in == nil {
		return nil
	}
	out := new(IngressNodeProtocolConfig)
	in.DeepCopyInto(out)
	return out
}
