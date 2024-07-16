package bpf_mgr

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/openshift/ingress-node-firewall/api/v1alpha1"

	bpfmaniov1alpha1 "github.com/bpfman/bpfman-operator/apis/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	debugLookup                = "debug_lookup" // constant defined in kernel hook to enable lPM lookup
	ingressNodeFirewallApp     = "ingress-node-firewall"
	ingressNodeFirewallXDPHook = "xdp_ingress_node_firewall_process"
	ingressNodeFirewallTCXHook = "tcx_ingress_node_firewall_process"
	ingressDirection           = "ingress"
	ingressNodeFirewallBCImage = "quay.io/bpfman-bytecode/ingress-node-firewall"
)

func BpfmanAttachNodeFirewall(ctx context.Context, client client.Client, obj *v1alpha1.IngressNodeFirewall, dbg bool) error {
	return bpfmanCreateNodeFirewallApplication(ctx, client, obj, dbg, false)
}

func BpfmanDetachNodeFirewall(ctx context.Context, client client.Client, obj *v1alpha1.IngressNodeFirewall, dbg bool) error {
	return bpfmanCreateNodeFirewallApplication(ctx, client, obj, dbg, true)
}

func bpfmanCreateNodeFirewallApplication(ctx context.Context, c client.Client, obj *v1alpha1.IngressNodeFirewall, dbg, isDelete bool) error {
	var err error
	bpfApp := bpfmaniov1alpha1.BpfApplication{}

	if isDelete {
		err := c.Get(ctx, client.ObjectKey{Name: ingressNodeFirewallApp}, &bpfApp)
		if err != nil {
			return fmt.Errorf("failed to get BpfApplication: %v", err)
		}
		klog.Info("Deleting BpfApplication Object")
		err = c.Delete(ctx, &bpfApp)
		if err != nil {
			return fmt.Errorf("failed to delete BpfApplication: %v", err)
		}
		return nil
	}

	interfaces := obj.Spec.Interfaces

	debug := make([]byte, 4)
	var value uint32

	if dbg {
		value = 1
	}
	binary.NativeEndian.PutUint32(debug, value)
	bpfApp.Spec.BpfAppCommon.GlobalData = map[string][]byte{
		debugLookup: debug,
	}

	bpfApp.Name = ingressNodeFirewallApp
	bpfApp.Kind = "BpfApplication"
	bpfApp.Labels = map[string]string{
		"app": ingressNodeFirewallApp,
	}
	bpfApp.Spec.NodeSelector = obj.Spec.NodeSelector

	bpfApp.Spec.BpfAppCommon.ByteCode = bpfmaniov1alpha1.BytecodeSelector{
		Image: &bpfmaniov1alpha1.BytecodeImage{
			Url:             ingressNodeFirewallBCImage,
			ImagePullPolicy: bpfmaniov1alpha1.PullAlways,
		},
	}
	bpfApp.Spec.BpfAppCommon.GlobalData = map[string][]byte{}
	bpfApp.Spec.Programs = []bpfmaniov1alpha1.BpfApplicationProgram{
		{
			Type: bpfmaniov1alpha1.ProgTypeXDP,
			XDP: &bpfmaniov1alpha1.XdpProgramInfo{
				BpfProgramCommon: bpfmaniov1alpha1.BpfProgramCommon{
					BpfFunctionName: ingressNodeFirewallXDPHook,
				},
				InterfaceSelector: bpfmaniov1alpha1.InterfaceSelector{Interfaces: &interfaces},
			},
		},
		/*
			{
				Type: bpfmaniov1alpha1.ProgTypeTCX,
				TCX: &bpfmaniov1alpha1.TcProgramInfo{
					BpfProgramCommon: bpfmaniov1alpha1.BpfProgramCommon{
						BpfFunctionName: ingressNodeFirewallTCXHook,
					},
					InterfaceSelector: bpfmaniov1alpha1.InterfaceSelector{Interfaces: &[]string{intf}},
					Direction:         ingressDirection,
				},
			},
		*/
	}

	err = c.Get(ctx, client.ObjectKey{Name: ingressNodeFirewallApp}, &bpfApp)
	if err != nil {
		if errors.IsNotFound(err) {
			klog.Info("Creating BpfApplication Object")

			err = c.Create(ctx, &bpfApp)
			if err != nil {
				return fmt.Errorf("failed to create BpfApplication: %v", err)
			}
		} else {
			return fmt.Errorf("failed to get BpfApplication: %v", err)
		}
	} else {
		klog.Info("Updating BpfApplication Object")
		err = c.Update(ctx, &bpfApp)
		if err != nil {
			return fmt.Errorf("failed to create BpfApplication: %v", err)

		}
	}

	return err
}
